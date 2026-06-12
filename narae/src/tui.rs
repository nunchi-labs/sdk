use crate::{
    config::Config,
    process::{Node, NodeStatus},
};
use ansi_to_tui::IntoText;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::{
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

type SharedNode = Arc<Mutex<Node>>;

#[derive(PartialEq, Eq)]
enum InputMode {
    Normal,
    Filter,
}

struct App {
    title: String,
    nodes: Vec<SharedNode>,
    selected: usize,
    scroll_offset: usize,
    should_quit: Arc<AtomicBool>,
    workspace: PathBuf,
    input_mode: InputMode,
    filter_input: String,
    log_filter: Option<String>,
}

impl App {
    fn new(config: Config, workspace: PathBuf) -> Self {
        let nodes = config
            .nodes
            .into_iter()
            .map(Node::new)
            .map(|node| Arc::new(Mutex::new(node)))
            .collect();
        Self {
            title: config.title,
            nodes,
            selected: 0,
            scroll_offset: 0,
            should_quit: Arc::new(AtomicBool::new(false)),
            workspace,
            input_mode: InputMode::Normal,
            filter_input: String::new(),
            log_filter: None,
        }
    }

    fn start_all(&self) {
        for node in &self.nodes {
            let result = Node::start(node, self.workspace.clone(), self.should_quit.clone());
            if let Err(error) = result {
                let mut node = node.lock().unwrap();
                node.status = NodeStatus::Error;
                node.add_log(format!("failed to start node: {error}"));
            }
        }
    }

    fn refresh(&self) {
        for node in &self.nodes {
            node.lock().unwrap().refresh();
        }
    }

    fn select_next(&mut self) {
        if self.nodes.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.nodes.len();
        self.scroll_offset = 0;
    }

    fn select_previous(&mut self) {
        if self.nodes.is_empty() {
            return;
        }
        self.selected = self.selected.checked_sub(1).unwrap_or(self.nodes.len() - 1);
        self.scroll_offset = 0;
    }

    fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
    }

    fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    fn select_node(&mut self, index: usize) {
        if index < self.nodes.len() {
            self.selected = index;
            self.scroll_offset = 0;
        }
    }

    fn restart_selected(&mut self) {
        let Some(node) = self.nodes.get(self.selected) else {
            return;
        };
        let result = Node::start(node, self.workspace.clone(), self.should_quit.clone());
        if let Err(error) = result {
            let mut node = node.lock().unwrap();
            node.status = NodeStatus::Error;
            node.add_log(format!("failed to restart node: {error}"));
        }
    }

    fn shutdown_selected(&mut self) {
        if let Some(node) = self.nodes.get(self.selected) {
            node.lock().unwrap().stop();
        }
    }

    fn shutdown_all(&mut self) {
        for node in &self.nodes {
            node.lock().unwrap().stop();
        }
    }
}

pub fn run(config: Config, workspace: PathBuf) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, config, workspace);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    config: Config,
    workspace: PathBuf,
) -> io::Result<()> {
    let mut app = App::new(config, workspace);
    app.start_all();

    loop {
        app.refresh();
        terminal.draw(|frame| ui(frame, &app))?;

        if event::poll(Duration::from_millis(100))? {
            let event = event::read()?;
            if let Event::Key(key) = event {
                if key.kind == KeyEventKind::Press {
                    handle_key(&mut app, key.code);
                    if app.should_quit.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
    }

    app.should_quit.store(true, Ordering::Relaxed);
    app.shutdown_all();
    Ok(())
}

fn handle_key(app: &mut App, code: KeyCode) {
    match app.input_mode {
        InputMode::Filter => match code {
            KeyCode::Enter => {
                app.log_filter = (!app.filter_input.is_empty()).then(|| app.filter_input.clone());
                app.scroll_offset = 0;
                app.input_mode = InputMode::Normal;
            }
            KeyCode::Esc => {
                app.filter_input.clear();
                app.log_filter = None;
                app.scroll_offset = 0;
                app.input_mode = InputMode::Normal;
            }
            KeyCode::Backspace => {
                app.filter_input.pop();
            }
            KeyCode::Char(c) => app.filter_input.push(c),
            _ => {}
        },
        InputMode::Normal => match code {
            KeyCode::Char('q') => app.should_quit.store(true, Ordering::Relaxed),
            KeyCode::Esc => {
                if app.log_filter.is_some() {
                    app.log_filter = None;
                    app.filter_input.clear();
                    app.scroll_offset = 0;
                } else {
                    app.should_quit.store(true, Ordering::Relaxed);
                }
            }
            KeyCode::Char('/') => {
                app.filter_input.clear();
                app.input_mode = InputMode::Filter;
            }
            KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
            KeyCode::Down | KeyCode::Char('j') => app.select_next(),
            KeyCode::PageUp => app.scroll_up(),
            KeyCode::PageDown => app.scroll_down(),
            KeyCode::Char('s') => app.shutdown_selected(),
            KeyCode::Char('S') => app.shutdown_all(),
            KeyCode::Char('r') => app.restart_selected(),
            KeyCode::Char(c) if c.is_ascii_digit() => {
                app.select_node(c.to_digit(10).unwrap() as usize);
            }
            _ => {}
        },
    }
}

fn ui(frame: &mut Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(20)])
        .split(frame.area());

    render_sidebar(frame, app, chunks[0]);
    render_logs(frame, app, chunks[1]);
    render_help(frame, app);
}

fn render_sidebar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let items = app
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let node = node.lock().unwrap();
            let selected = index == app.selected;
            let style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let status_style = Style::default().fg(status_color(node.status));
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", node.status.symbol()), status_style),
                Span::styled(node.spec.name.clone(), style),
            ]))
        })
        .collect::<Vec<_>>();

    let mut state = ListState::default();
    state.select(Some(app.selected));
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Nodes "))
        .highlight_style(Style::default().bg(Color::DarkGray));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_logs(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let bottom_offset = if app.input_mode == InputMode::Filter || app.log_filter.is_some() {
        2
    } else {
        1
    };
    let log_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: area.height.saturating_sub(bottom_offset),
    };

    let Some(node) = app.nodes.get(app.selected) else {
        return;
    };
    let node = node.lock().unwrap();
    let visible_height = log_area.height.saturating_sub(2) as usize;
    let filter = app.log_filter.as_ref().map(|filter| filter.to_lowercase());
    let logs = node
        .logs
        .iter()
        .filter(|line| {
            filter
                .as_ref()
                .is_none_or(|filter| line.to_lowercase().contains(filter))
        })
        .collect::<Vec<_>>();
    let lines = logs
        .iter()
        .rev()
        .skip(app.scroll_offset)
        .take(visible_height)
        .rev()
        .map(|line| {
            line.as_bytes()
                .into_text()
                .ok()
                .and_then(|text| text.lines.into_iter().next())
                .unwrap_or_else(|| Line::from((*line).clone()))
        })
        .collect::<Vec<_>>();

    let title = match &app.log_filter {
        Some(filter) => format!(" {} [filter: {filter}] ", node.spec.name),
        None => format!(" {} - {} ", app.title, node.spec.name),
    };
    let logs = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(logs, log_area);

    if app.input_mode == InputMode::Filter || app.log_filter.is_some() {
        render_filter(frame, app);
    }
}

fn render_filter(frame: &mut Frame<'_>, app: &App) {
    let area = Rect {
        x: 0,
        y: frame.area().height.saturating_sub(2),
        width: frame.area().width,
        height: 1,
    };
    let text = if app.input_mode == InputMode::Filter {
        format!(" /{}", app.filter_input)
    } else {
        format!(
            " filter: {} (esc clears)",
            app.log_filter.as_deref().unwrap_or("")
        )
    };
    frame.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::White).bg(Color::Rgb(35, 35, 35))),
        area,
    );
}

fn render_help(frame: &mut Frame<'_>, app: &App) {
    let area = Rect {
        x: 0,
        y: frame.area().height.saturating_sub(1),
        width: frame.area().width,
        height: 1,
    };
    let shutdown = if app.nodes.len() > 1 {
        "s stop  S stop all"
    } else {
        "s stop"
    };
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" up/down ", Style::default().fg(Color::Yellow)),
        Span::raw("select  "),
        Span::styled(" pgup/pgdn ", Style::default().fg(Color::Yellow)),
        Span::raw("scroll  "),
        Span::styled(" / ", Style::default().fg(Color::Yellow)),
        Span::raw("filter  "),
        Span::styled(" r ", Style::default().fg(Color::Yellow)),
        Span::raw("restart  "),
        Span::styled(format!(" {shutdown} "), Style::default().fg(Color::Yellow)),
        Span::raw("  "),
        Span::styled(" q ", Style::default().fg(Color::Yellow)),
        Span::raw("quit"),
    ]))
    .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(help, area);
}

fn status_color(status: NodeStatus) -> Color {
    match status {
        NodeStatus::Starting => Color::Yellow,
        NodeStatus::Running => Color::Green,
        NodeStatus::Error => Color::Red,
        NodeStatus::Stopped => Color::Gray,
    }
}
