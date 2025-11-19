use crate::proto::{GetServiceLogsRequest, GetServiceLogsResponse, LogFileInfo};
use crate::TappResult;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct LogsService {
    log_dir: Option<PathBuf>,
}

impl LogsService {
    pub fn new(log_file_path: Option<PathBuf>) -> Self {
        // Extract directory from log file path
        let log_dir = log_file_path.and_then(|path| {
            if path.is_dir() {
                Some(path)
            } else {
                path.parent().map(|p| p.to_path_buf())
            }
        });

        Self { log_dir }
    }

    /// Get service logs: list files or return file content
    pub async fn get_logs(&self, request: GetServiceLogsRequest) -> TappResult<GetServiceLogsResponse> {
        let log_dir = match &self.log_dir {
            Some(dir) => dir,
            None => {
                return Ok(GetServiceLogsResponse {
                    success: false,
                    message: "Logging to file is not configured".to_string(),
                    available_files: vec![],
                    content: String::new(),
                    total_lines: 0,
                });
            }
        };

        // If file_name is empty, list all available log files
        if request.file_name.is_empty() {
            let files = self.list_log_files(log_dir).await?;
            return Ok(GetServiceLogsResponse {
                success: true,
                message: format!("Found {} log file(s)", files.len()),
                available_files: files,
                content: String::new(),
                total_lines: 0,
            });
        }

        // Otherwise, return the specified file's content
        let file_path = log_dir.join(&request.file_name);
        let lines = if request.lines > 0 { request.lines as usize } else { 100 };

        let content = self.read_log_file(&file_path, lines).await?;
        let total_lines = content.lines().count() as i32;

        Ok(GetServiceLogsResponse {
            success: true,
            message: format!("Retrieved {} lines from {}", total_lines, request.file_name),
            available_files: vec![],
            content,
            total_lines,
        })
    }

    /// List all log files in the directory
    async fn list_log_files(&self, dir: &PathBuf) -> TappResult<Vec<LogFileInfo>> {
        let mut files = Vec::new();

        let mut entries = fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Only include files (not directories)
            if !path.is_file() {
                continue;
            }

            let file_name = entry.file_name().to_string_lossy().to_string();

            // Get file metadata
            if let Ok(metadata) = entry.metadata().await {
                let size_bytes = metadata.len() as i64;
                let modified_time = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                files.push(LogFileInfo {
                    file_name,
                    size_bytes,
                    modified_time,
                });
            }
        }

        // Sort by modified time (newest first)
        files.sort_by(|a, b| b.modified_time.cmp(&a.modified_time));

        Ok(files)
    }

    /// Read last N lines from a log file (tail -n behavior)
    async fn read_log_file(&self, path: &PathBuf, max_lines: usize) -> TappResult<String> {
        if !path.exists() {
           return Err(crate::TappError::InvalidParameter {
                field: "file_name".to_string(),
                reason: format!("Log file not found: {:?}", path), 
           });
        }

        let file = fs::File::open(path).await?;
        let reader = BufReader::new(file);
        let mut lines_stream = reader.lines();

        // Read all lines
        let mut all_lines = Vec::new();
        while let Some(line) = lines_stream.next_line().await? {
            all_lines.push(line);
        }

        // Take last N lines (tail behavior)
        let start_index = if all_lines.len() > max_lines {
            all_lines.len() - max_lines
        } else {
            0
        };

        let content = all_lines[start_index..].join("\n");
        Ok(content)
    }
}

