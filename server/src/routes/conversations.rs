//! Conversations, membership, retention, messages and delete-for-everyone.
//!
//! Non-members get 404 for everything, so conversation ids leak nothing.

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use sqlx::postgres::PgRow;
use ssm_proto::B64;
use ssm_proto::api::{
    AddMemberRequest, ConversationInfo, ConversationKind, CreateConversationRequest, DEFAULT_RETENTION_DAYS,
    DeleteJobInfo, DeleteJobStatus, DeleteRequest, EventBody, MAX_RETENTION_DAYS, MIN_RETENTION_DAYS, MemberInfo,
    MessageBody, MessageItem, MessagesPage, PAGE_SIZE, RetentionRequest, SendMessageRequest, SendMessageResponse,
    SystemNotice,
};
use uuid::Uuid;

use crate::AppState;
use crate::auth::ActiveDevice;
use crate::conversations::{self, Conversation, Membership, NewJob, NewMessage};
use crate::error::{ApiError, ApiResult};

pub const MAX_GROUP_MEMBERS: usize = 256;
pub const MAX_CIPHERTEXT: usize = 64 * 1024;

fn rfc3339(row: &PgRow, column: &str) -> ApiResult<String> {
    Ok(row.try_get::<DateTime<Utc>, _>(column)?.to_rfc3339())
}

fn check_retention(days: u16) -> ApiResult<()> {
    if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!("retention must be {MIN_RETENTION_DAYS}-{MAX_RETENTION_DAYS} days")));
    }
    Ok(())
}

/// Locks the conversation and checks that `account` is an active member.
async fn member_lock(
    conn: &mut sqlx::PgConnection,
    conversation_id: Uuid,
    account: Uuid,
) -> ApiResult<(Conversation, Membership)> {
    let conv = conversations::lock(conn, conversation_id).await?.ok_or_else(ApiError::not_found)?;
    let membership =
        conversations::membership(conn, conversation_id, account).await?.ok_or_else(ApiError::not_found)?;
    Ok((conv, membership))
}

async fn load_info(pool: &sqlx::PgPool, conversation_id: Uuid) -> ApiResult<ConversationInfo> {
    let row = sqlx::query(
        "SELECT kind, retention_days, created_by, created_at, message_seq FROM conversations WHERE id = $1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await?;
    let members = sqlx::query(
        "SELECT m.account_id, a.username, m.status, m.role FROM conversation_members m
         JOIN accounts a ON a.id = m.account_id
         WHERE m.conversation_id = $1 ORDER BY a.username",
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await?
    .iter()
    .map(|m| {
        Ok(MemberInfo {
            account_id: m.try_get("account_id")?,
            username: m.try_get("username")?,
            status: m.try_get("status")?,
            role: m.try_get("role")?,
        })
    })
    .collect::<ApiResult<Vec<_>>>()?;
    Ok(ConversationInfo {
        conversation_id,
        kind: ConversationKind::parse(row.try_get("kind")?).ok_or_else(ApiError::internal)?,
        retention_days: row.try_get::<i32, _>("retention_days")? as u16,
        created_by: row.try_get("created_by")?,
        created_at: rfc3339(&row, "created_at")?,
        last_seq: row.try_get("message_seq")?,
        members,
    })
}

/// Creates a direct chat (exactly one other member; an existing one is
/// returned) or a group. The caller is always a member.
pub async fn create(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Json(req): Json<CreateConversationRequest>,
) -> ApiResult<Json<ConversationInfo>> {
    let retention = req.retention_days.unwrap_or(DEFAULT_RETENTION_DAYS);
    check_retention(retention)?;
    let mut others = req.members;
    others.sort();
    others.dedup();
    others.retain(|id| *id != device.account_id);
    match req.kind {
        ConversationKind::Direct if others.len() != 1 => {
            return Err(ApiError::bad_request("a direct conversation has exactly one other member"));
        }
        ConversationKind::Group if others.len() + 1 > MAX_GROUP_MEMBERS => {
            return Err(ApiError::bad_request(format!("a group has at most {MAX_GROUP_MEMBERS} members")));
        }
        _ => {}
    }

    let mut tx = state.pool.begin().await?;
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE id = ANY($1) AND status = 'active'")
        .bind(&others)
        .fetch_one(&mut *tx)
        .await?;
    if active != others.len() as i64 {
        return Err(ApiError::bad_request("unknown or inactive member"));
    }

    if req.kind == ConversationKind::Direct {
        let (a, b) = (device.account_id.min(others[0]), device.account_id.max(others[0]));
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("direct:{a}:{b}"))
            .execute(&mut *tx)
            .await?;
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT c.id FROM conversations c
             JOIN conversation_members x ON x.conversation_id = c.id AND x.account_id = $1 AND x.status = 'active'
             JOIN conversation_members y ON y.conversation_id = c.id AND y.account_id = $2 AND y.status = 'active'
             WHERE c.kind = 'direct' LIMIT 1",
        )
        .bind(a)
        .bind(b)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(id) = existing {
            tx.commit().await?;
            return Ok(Json(load_info(&state.pool, id).await?));
        }
    }

    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO conversations (id, kind, retention_days, created_by) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(req.kind.as_str())
        .bind(i32::from(retention))
        .bind(device.account_id)
        .execute(&mut *tx)
        .await?;
    // The creator administers the group; in direct chats the role has no effect.
    sqlx::query(
        "INSERT INTO conversation_members (conversation_id, account_id, role)
         SELECT $1, member, CASE WHEN member = $3 THEN 'admin' ELSE 'member' END
         FROM unnest($2::uuid[]) AS member",
    )
    .bind(id)
    .bind([vec![device.account_id], others].concat())
    .bind(device.account_id)
    .execute(&mut *tx)
    .await?;
    let conv = conversations::lock(&mut tx, id).await?.ok_or_else(ApiError::internal)?;
    let woken =
        conversations::notice(&mut tx, &conv, SystemNotice::ConversationCreated { by: device.account_id }).await?;
    tx.commit().await?;
    state.wake(&woken);
    Ok(Json(load_info(&state.pool, id).await?))
}

pub async fn list(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
) -> ApiResult<Json<Vec<ConversationInfo>>> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT m.conversation_id FROM conversation_members m
         JOIN conversations c ON c.id = m.conversation_id
         WHERE m.account_id = $1 AND m.status = 'active' ORDER BY c.created_at",
    )
    .bind(device.account_id)
    .fetch_all(&state.pool)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(load_info(&state.pool, id).await?);
    }
    Ok(Json(out))
}

pub async fn get(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ConversationInfo>> {
    let mut conn = state.pool.acquire().await?;
    conversations::active_membership(&mut conn, id, device.account_id).await?.ok_or_else(ApiError::not_found)?;
    Ok(Json(load_info(&state.pool, id).await?))
}

/// Only the group admin may add members.
pub async fn add_member(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<Json<ConversationInfo>> {
    let mut tx = state.pool.begin().await?;
    let (conv, me) = member_lock(&mut tx, id, device.account_id).await?;
    if conv.kind != ConversationKind::Group {
        return Err(ApiError::bad_request("members can only be added to groups"));
    }
    if !me.is_admin {
        return Err(ApiError::forbidden("only-admin-can-invite"));
    }
    let active: Option<Uuid> = sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1 AND status = 'active'")
        .bind(req.account_id)
        .fetch_optional(&mut *tx)
        .await?;
    active.ok_or_else(|| ApiError::bad_request("unknown or inactive account"))?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM conversation_members WHERE conversation_id = $1 AND status = 'active'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if count as usize >= MAX_GROUP_MEMBERS {
        return Err(ApiError::conflict("group-full"));
    }
    let added = sqlx::query(
        "INSERT INTO conversation_members (conversation_id, account_id, joined_seq)
         SELECT $1, $2, message_seq FROM conversations WHERE id = $1
         ON CONFLICT (conversation_id, account_id) DO UPDATE
             SET status = 'active', joined_at = now(), left_at = NULL, joined_seq = EXCLUDED.joined_seq
             WHERE conversation_members.status <> 'active'",
    )
    .bind(id)
    .bind(req.account_id)
    .execute(&mut *tx)
    .await?;
    if added.rows_affected() == 0 {
        return Err(ApiError::conflict("already-member"));
    }
    let woken = conversations::notice(
        &mut tx,
        &conv,
        SystemNotice::MemberAdded { account_id: req.account_id, by: device.account_id },
    )
    .await?;
    tx.commit().await?;
    state.wake(&woken);
    Ok(Json(load_info(&state.pool, id).await?))
}

/// Leaving a group is always allowed; removing someone else is reserved to
/// the group admin. If the admin leaves, the longest-standing member takes over.
pub async fn remove_member(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path((id, account_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<ConversationInfo>> {
    let mut tx = state.pool.begin().await?;
    let (conv, me) = member_lock(&mut tx, id, device.account_id).await?;
    if conv.kind != ConversationKind::Group {
        return Err(ApiError::bad_request("members can only leave or be removed from groups"));
    }
    let leaving = account_id == device.account_id;
    if !leaving && !me.is_admin {
        return Err(ApiError::forbidden("only-admin-can-remove"));
    }
    // Woken before the status change so the leaving member's devices see the update.
    let notice = if leaving {
        SystemNotice::MemberLeft { account_id }
    } else {
        SystemNotice::MemberRemoved { account_id, by: device.account_id }
    };
    let woken = conversations::notice(&mut tx, &conv, notice).await?;
    let updated = sqlx::query(
        "UPDATE conversation_members SET status = $3, role = 'member', left_at = now()
         WHERE conversation_id = $1 AND account_id = $2 AND status = 'active'",
    )
    .bind(id)
    .bind(account_id)
    .bind(if leaving { "left" } else { "removed" })
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    let mut woken = woken;
    if let Some(new_admin) = conversations::ensure_admin(&mut tx, id).await? {
        woken
            .extend(conversations::notice(&mut tx, &conv, SystemNotice::AdminChanged { account_id: new_admin }).await?);
    }
    tx.commit().await?;
    state.wake(&woken);
    Ok(Json(load_info(&state.pool, id).await?))
}

/// Any active member may change the retention period. Existing messages get
/// the new expiry right away; everybody sees a notice in the timeline.
pub async fn set_retention(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(id): Path<Uuid>,
    Json(req): Json<RetentionRequest>,
) -> ApiResult<Json<ConversationInfo>> {
    check_retention(req.days)?;
    let mut tx = state.pool.begin().await?;
    let (mut conv, _) = member_lock(&mut tx, id, device.account_id).await?;
    let from_days = conv.retention_days as u16;
    if from_days != req.days {
        sqlx::query("UPDATE conversations SET retention_days = $2 WHERE id = $1")
            .bind(id)
            .bind(i32::from(req.days))
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE messages SET expires_at = created_at + make_interval(days => $2) WHERE conversation_id = $1",
        )
        .bind(id)
        .bind(i32::from(req.days))
        .execute(&mut *tx)
        .await?;
        conv.retention_days = req.days.into();
        let notice = SystemNotice::RetentionChanged { from_days, to_days: req.days, by: device.account_id };
        let woken = conversations::notice(&mut tx, &conv, notice).await?;
        tx.commit().await?;
        state.wake(&woken);
    }
    Ok(Json(load_info(&state.pool, id).await?))
}

pub async fn send(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(id): Path<Uuid>,
    Json(req): Json<SendMessageRequest>,
) -> ApiResult<Json<SendMessageResponse>> {
    if req.ciphertext.0.is_empty() || req.ciphertext.0.len() > MAX_CIPHERTEXT {
        return Err(ApiError::bad_request(format!("ciphertext must be 1-{MAX_CIPHERTEXT} bytes")));
    }
    if req.session_id.is_empty() || req.session_id.len() > 128 {
        return Err(ApiError::bad_request("session_id must be 1-128 characters"));
    }
    let mut tx = state.pool.begin().await?;
    let (conv, _) = member_lock(&mut tx, id, device.account_id).await?;

    // Idempotent retry: same device + client_id returns the stored message.
    let existing = sqlx::query(
        "SELECT id, conversation_id, seq, created_at, expires_at FROM messages
         WHERE sender_device_id = $1 AND client_id = $2",
    )
    .bind(device.device_id)
    .bind(req.client_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        if row.try_get::<Uuid, _>("conversation_id")? != id {
            return Err(ApiError::conflict("client-id-reused"));
        }
        return Ok(Json(SendMessageResponse {
            message_id: row.try_get("id")?,
            seq: row.try_get("seq")?,
            created_at: rfc3339(&row, "created_at")?,
            expires_at: rfc3339(&row, "expires_at")?,
        }));
    }

    let stored = conversations::append(
        &mut tx,
        &conv,
        NewMessage {
            sender_account_id: Some(device.account_id),
            sender_device_id: Some(device.device_id),
            client_id: Some(req.client_id),
            encrypted: Some((&req.session_id, &req.ciphertext.0)),
            notice: None,
        },
    )
    .await?;
    if !req.media_ids.is_empty() {
        if req.media_ids.len() > 2 {
            return Err(ApiError::bad_request("at most two media objects (original and preview) per message"));
        }
        // Only this device's unsent uploads for this conversation.
        let linked = sqlx::query(
            "UPDATE media_objects SET message_id = $1
             WHERE id = ANY($2) AND conversation_id = $3 AND uploader_device_id = $4 AND message_id IS NULL",
        )
        .bind(stored.id)
        .bind(&req.media_ids)
        .bind(id)
        .bind(device.device_id)
        .execute(&mut *tx)
        .await?;
        if linked.rows_affected() != req.media_ids.len() as u64 {
            return Err(ApiError::bad_request("unknown or already used media id"));
        }
    }
    let event = EventBody::Message { conversation_id: id, seq: stored.seq };
    let woken = conversations::fan_out(&mut tx, id, &event, Some(device.device_id)).await?;
    tx.commit().await?;
    state.wake(&woken);
    Ok(Json(SendMessageResponse {
        message_id: stored.id,
        seq: stored.seq,
        created_at: stored.created_at.to_rfc3339(),
        expires_at: stored.expires_at.to_rfc3339(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    /// Newest-first page of messages with `seq < before` (default: latest).
    before: Option<i64>,
    /// Oldest-first messages with `seq > after` (catching up after an event).
    after: Option<i64>,
    limit: Option<i64>,
}

fn message_item(row: &PgRow) -> ApiResult<MessageItem> {
    let body =
        match (row.try_get::<String, _>("kind")?.as_str(), row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?) {
            (_, Some(deleted_at)) => {
                MessageBody::Deleted { deleted_by: row.try_get("deleted_by")?, deleted_at: deleted_at.to_rfc3339() }
            }
            ("encrypted", None) => MessageBody::Encrypted {
                session_id: row.try_get::<Option<String>, _>("session_id")?.ok_or_else(ApiError::internal)?,
                ciphertext: B64(row.try_get::<Option<Vec<u8>>, _>("ciphertext")?.ok_or_else(ApiError::internal)?),
            },
            _ => MessageBody::System {
                notice: serde_json::from_value(row.try_get("notice")?).map_err(|_| ApiError::internal())?,
            },
        };
    Ok(MessageItem {
        message_id: row.try_get("id")?,
        seq: row.try_get("seq")?,
        sender_account_id: row.try_get("sender_account_id")?,
        sender_device_id: row.try_get("sender_device_id")?,
        created_at: rfc3339(row, "created_at")?,
        expires_at: rfc3339(row, "expires_at")?,
        body,
    })
}

/// Cursor pagination, at most 100 per page (FR-006). Expired messages and
/// messages from before the caller joined are never returned.
pub async fn messages(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<MessagesPage>> {
    if query.before.is_some() && query.after.is_some() {
        return Err(ApiError::bad_request("use either before or after"));
    }
    let limit = query.limit.unwrap_or(PAGE_SIZE).clamp(1, PAGE_SIZE);
    let mut conn = state.pool.acquire().await?;
    let joined_seq =
        conversations::active_membership(&mut conn, id, device.account_id).await?.ok_or_else(ApiError::not_found)?;

    const COLUMNS: &str = "id, seq, kind, sender_account_id, sender_device_id, session_id, ciphertext, notice,
                           created_at, expires_at, deleted_at, deleted_by";
    let rows = if let Some(after) = query.after {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM messages
             WHERE conversation_id = $1 AND expires_at > now() AND seq > $2 AND seq > $3
             ORDER BY seq ASC LIMIT $4"
        )))
        .bind(id)
        .bind(joined_seq)
        .bind(after)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM messages
             WHERE conversation_id = $1 AND expires_at > now() AND seq > $2 AND ($3::bigint IS NULL OR seq < $3)
             ORDER BY seq DESC LIMIT $4"
        )))
        .bind(id)
        .bind(joined_seq)
        .bind(query.before)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?
    };
    let messages = rows.iter().map(message_item).collect::<ApiResult<Vec<_>>>()?;
    let next_before = match query.after {
        None if messages.len() as i64 == limit => messages.last().map(|m| m.seq),
        _ => None,
    };
    Ok(Json(MessagesPage { messages, next_before }))
}

pub(crate) async fn job_info(conn: &mut sqlx::PgConnection, job_id: Uuid) -> ApiResult<DeleteJobInfo> {
    let row = sqlx::query(
        "SELECT id, operation_id, status, affected_messages, created_at, updated_at, backup_purge_due_at, error_summary
         FROM delete_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(conn)
    .await?;
    Ok(DeleteJobInfo {
        job_id: row.try_get("id")?,
        operation_id: row.try_get("operation_id")?,
        status: DeleteJobStatus::parse(row.try_get("status")?).ok_or_else(ApiError::internal)?,
        affected_messages: row.try_get("affected_messages")?,
        created_at: rfc3339(&row, "created_at")?,
        updated_at: rfc3339(&row, "updated_at")?,
        backup_purge_due_at: row.try_get::<Option<DateTime<Utc>>, _>("backup_purge_due_at")?.map(|t| t.to_rfc3339()),
        error_summary: row.try_get("error_summary")?,
    })
}

/// The only deletion there is: for everyone (FR-007). Any active member may
/// delete any message of the conversation (ADR-0004). Idempotent per
/// `operation_id`; deleting an already deleted message returns its job.
pub async fn delete_for_all(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(message_id): Path<Uuid>,
    Json(req): Json<DeleteRequest>,
) -> ApiResult<Json<DeleteJobInfo>> {
    let mut tx = state.pool.begin().await?;
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM delete_jobs WHERE requested_by = $1 AND operation_id = $2")
            .bind(device.account_id)
            .bind(req.operation_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(job_id) = existing {
        return Ok(Json(job_info(&mut tx, job_id).await?));
    }

    let conversation_id: Uuid =
        sqlx::query_scalar("SELECT conversation_id FROM messages WHERE id = $1 AND expires_at > now()")
            .bind(message_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(ApiError::not_found)?;
    let (conv, Membership { joined_seq, .. }) = member_lock(&mut tx, conversation_id, device.account_id).await?;
    let row = sqlx::query("SELECT kind, seq, delete_job_id FROM messages WHERE id = $1 FOR UPDATE")
        .bind(message_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if row.try_get::<i64, _>("seq")? <= joined_seq {
        return Err(ApiError::not_found());
    }
    if row.try_get::<String, _>("kind")? != "encrypted" {
        return Err(ApiError::conflict("not-deletable").with_detail("system notices cannot be deleted"));
    }
    if let Some(job_id) = row.try_get::<Option<Uuid>, _>("delete_job_id")? {
        return Ok(Json(job_info(&mut tx, job_id).await?));
    }

    let job = NewJob {
        id: Uuid::new_v4(),
        operation_id: req.operation_id,
        requested_by: Some(device.account_id),
        requested_by_admin: false,
        scope: json!({ "type": "message", "conversation_id": conversation_id, "message_id": message_id }),
    };
    conversations::insert_job(&mut tx, &job, DeleteJobStatus::InProgress).await?;
    let (affected, woken) =
        conversations::delete_messages(&mut tx, &conv, &[message_id], Some(device.account_id), job.id).await?;
    conversations::finish_active_removal(&mut tx, job.id, affected, state.config.backup_retention_days).await?;
    let info = job_info(&mut tx, job.id).await?;
    tx.commit().await?;
    state.wake(&woken);
    crate::media::purge_soon(&state);
    tracing::info!(job_id = %job.id, %conversation_id, "message deleted for everyone");
    Ok(Json(info))
}

/// Visible to the requester and to active members of the affected conversation.
pub async fn delete_job(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(job_id): Path<Uuid>,
) -> ApiResult<Json<DeleteJobInfo>> {
    let mut conn = state.pool.acquire().await?;
    let visible: Option<Uuid> = sqlx::query_scalar(
        "SELECT j.id FROM delete_jobs j
         WHERE j.id = $1 AND (j.requested_by = $2 OR EXISTS (
             SELECT 1 FROM conversation_members m
             WHERE m.conversation_id = (j.scope->>'conversation_id')::uuid
               AND m.account_id = $2 AND m.status = 'active'))",
    )
    .bind(job_id)
    .bind(device.account_id)
    .fetch_optional(&mut *conn)
    .await?;
    visible.ok_or_else(ApiError::not_found)?;
    Ok(Json(job_info(&mut conn, job_id).await?))
}
