//! 5×5 unlock pattern input (ADR-0005). Pressed dots are not highlighted
//! beyond the button's normal pressed state, so no trail is visible; only the
//! number of presses is shown.

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;
use ssm_core::pattern::{DOT_COUNT, GRID_SIZE, MIN_LEN};
use ssm_core::{Pattern, PatternError};

pub struct PatternPad {
    pub widget: gtk::Box,
    presses: Rc<RefCell<Vec<u8>>>,
    count: gtk::Label,
}

fn count_text(n: usize) -> String {
    match n {
        0 => format!("Press at least {MIN_LEN} dots, in any order, as often as you like."),
        1 => "1 press".to_owned(),
        n => format!("{n} presses"),
    }
}

impl PatternPad {
    pub fn new() -> Rc<Self> {
        let widget = gtk::Box::new(gtk::Orientation::Vertical, 6);
        let grid = gtk::Grid::builder().row_spacing(4).column_spacing(4).halign(gtk::Align::Center).build();
        let count = gtk::Label::new(Some(&count_text(0)));
        let presses: Rc<RefCell<Vec<u8>>> = Rc::default();

        for dot in 0..DOT_COUNT {
            let button = gtk::Button::with_label("●");
            button.add_css_class("pattern-dot");
            button.set_focus_on_click(false);
            let (presses, count) = (presses.clone(), count.clone());
            button.connect_clicked(move |_| {
                let mut presses = presses.borrow_mut();
                if presses.len() < ssm_core::pattern::MAX_LEN {
                    presses.push(dot);
                }
                count.set_text(&count_text(presses.len()));
            });
            grid.attach(&button, i32::from(dot % GRID_SIZE), i32::from(dot / GRID_SIZE), 1, 1);
        }

        let clear = gtk::Button::with_label("Clear");
        clear.set_halign(gtk::Align::Center);
        widget.append(&grid);
        widget.append(&count);
        widget.append(&clear);
        let pad = Rc::new(Self { widget, presses, count });
        let weak = Rc::downgrade(&pad);
        clear.connect_clicked(move |_| {
            if let Some(pad) = weak.upgrade() {
                pad.clear();
            }
        });
        pad
    }

    /// Validates and returns the entered pattern, clearing the input.
    pub fn take(&self) -> Result<Pattern, PatternError> {
        let dots = std::mem::take(&mut *self.presses.borrow_mut());
        self.count.set_text(&count_text(0));
        Pattern::new(dots)
    }

    /// Debug builds only: enter a pattern programmatically.
    #[cfg(debug_assertions)]
    pub fn set(&self, dots: &[u8]) {
        self.presses.replace(dots.to_vec());
        self.count.set_text(&count_text(dots.len()));
    }

    pub fn clear(&self) {
        let mut presses = self.presses.borrow_mut();
        presses.iter_mut().for_each(|d| *d = 0);
        presses.clear();
        self.count.set_text(&count_text(0));
    }
}
