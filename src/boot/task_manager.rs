use crate::proto::{TaskResult, TaskStatus as ProtoTaskStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed(TaskSuccessResult),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct TaskSuccessResult {
    pub app_id: String,
    pub deployer: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: String,
    pub status: TaskStatus,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Task {
    pub fn new() -> Self {
        let now = crate::utils::current_timestamp();
        Self {
            id: format!("task-{}", Uuid::new_v4()),
            status: TaskStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn to_proto_status(&self) -> ProtoTaskStatus {
        match &self.status {
            TaskStatus::Pending => ProtoTaskStatus::Pending,
            TaskStatus::Running => ProtoTaskStatus::Running,
            TaskStatus::Completed(_) => ProtoTaskStatus::Completed,
            TaskStatus::Failed(_) => ProtoTaskStatus::Failed,
        }
    }

    pub fn to_proto_result(&self) -> Option<TaskResult> {
        match &self.status {
            TaskStatus::Completed(result) => Some(TaskResult {
                app_id: result.app_id.clone(),
                deployer: result.deployer.clone(),
                error: String::new(),
            }),
            TaskStatus::Failed(error) => Some(TaskResult {
                app_id: String::new(),
                deployer: vec![],
                error: error.clone(),
            }),
            _ => None,
        }
    }
}

pub struct TaskManager {
    tasks: Arc<RwLock<HashMap<String, Task>>>,
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_task(&self) -> Task {
        let task = Task::new();
        let mut tasks = self.tasks.write().await;
        tasks.insert(task.id.clone(), task.clone());
        task
    }

    pub async fn get_task(&self, task_id: &str) -> Option<Task> {
        let tasks = self.tasks.read().await;
        tasks.get(task_id).cloned()
    }

    pub async fn update_task_status(&self, task_id: &str, status: TaskStatus) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = status;
            task.updated_at = crate::utils::current_timestamp();
        }
    }

    pub async fn mark_running(&self, task_id: &str) {
        self.update_task_status(task_id, TaskStatus::Running).await;
    }

    pub async fn mark_completed(&self, task_id: &str, result: TaskSuccessResult) {
        self.update_task_status(task_id, TaskStatus::Completed(result))
            .await;
    }

    pub async fn mark_failed(&self, task_id: &str, error: String) {
        self.update_task_status(task_id, TaskStatus::Failed(error))
            .await;
    }
}
