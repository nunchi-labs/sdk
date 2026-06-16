use crate::config::NodeSpec;
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

const MAX_LOG_LINES: usize = 2_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Starting,
    Running,
    Error,
    Stopped,
}

impl NodeStatus {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Starting => "...",
            Self::Running => "ok",
            Self::Error => "!!",
            Self::Stopped => "--",
        }
    }
}

pub struct Node {
    pub spec: NodeSpec,
    pub status: NodeStatus,
    pub logs: VecDeque<String>,
    child: Option<Child>,
}

impl Node {
    pub fn new(spec: NodeSpec) -> Self {
        Self {
            spec,
            status: NodeStatus::Stopped,
            logs: VecDeque::with_capacity(MAX_LOG_LINES),
            child: None,
        }
    }

    pub fn command_line(&self) -> String {
        std::iter::once(self.spec.command.as_str())
            .chain(self.spec.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }

    // Status is judged by process lifecycle (spawn failures, exit codes), never by scanning log
    // content: chatty consensus logs contain transient "failed ..." lines on healthy nodes.
    pub fn add_log(&mut self, line: impl Into<String>) {
        if self.logs.len() == MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.logs.push_back(line.into());
    }

    pub fn start(
        node: &Arc<Mutex<Self>>,
        workspace: PathBuf,
        should_quit: Arc<AtomicBool>,
    ) -> Result<(), std::io::Error> {
        let (spec, command_line) = {
            let mut node = node.lock().unwrap();
            node.stop();
            node.status = NodeStatus::Starting;
            let command_line = node.command_line();
            node.add_log(format!("$ {command_line}"));
            (node.spec.clone(), command_line)
        };

        let mut command = Command::new(&spec.command);
        command.args(&spec.args);
        command.current_dir(spec.cwd.as_deref().map_or(workspace, PathBuf::from));
        for env in spec.env {
            command.env(env.key, env.value);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = command.spawn()?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        {
            let mut node = node.lock().unwrap();
            node.status = NodeStatus::Running;
            node.child = Some(child);
        }

        if let Some(stdout) = stdout {
            spawn_reader(Arc::clone(node), should_quit.clone(), stdout);
        }
        if let Some(stderr) = stderr {
            spawn_reader(Arc::clone(node), should_quit, stderr);
        }

        let mut node = node.lock().unwrap();
        node.add_log(format!("started: {command_line}"));
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            self.status = NodeStatus::Stopped;
            self.add_log("stopped");
        }
    }

    pub fn refresh(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                self.child = None;
                self.status = if status.success() {
                    NodeStatus::Stopped
                } else {
                    NodeStatus::Error
                };
                self.add_log(format!("exited with {status}"));
            }
            Ok(None) => {}
            Err(error) => {
                self.child = None;
                self.status = NodeStatus::Error;
                self.add_log(format!("failed to inspect process: {error}"));
            }
        }
    }
}

fn spawn_reader<R>(node: Arc<Mutex<Node>>, should_quit: Arc<AtomicBool>, reader: R)
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            if should_quit.load(Ordering::Relaxed) {
                break;
            }
            match line {
                Ok(line) => node.lock().unwrap().add_log(line),
                Err(error) => {
                    node.lock()
                        .unwrap()
                        .add_log(format!("failed to read process output: {error}"));
                    break;
                }
            }
        }
    });
}
