from datetime import datetime
from typing import Optional
import sqlite3
from pathlib import Path

from task_sync.models import Project, Task, User, Comment, WebhookSubscription
from task_sync.client import TaskSyncClient


class TaskSync:
    """Syncs tasks from API to local SQLite database."""

    def __init__(self, db_path: str = "tasksync.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    owner_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    synced_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    assignee_id TEXT,
                    reporter_id TEXT NOT NULL,
                    due_date TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    synced_at TEXT NOT NULL,
                    FOREIGN KEY (project_id) REFERENCES projects (id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    name TEXT NOT NULL,
                    avatar_url TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    synced_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    author_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    synced_at TEXT NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks (id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    events TEXT NOT NULL,
                    secret TEXT,
                    created_at TEXT NOT NULL,
                    synced_at TEXT NOT NULL
                )
            """)

    def sync_project(self, project: Project) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO projects (id, name, description, owner_id, created_at, updated_at, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                project.id, project.name, project.description, project.owner_id,
                project.created_at.isoformat(), project.updated_at.isoformat(),
                datetime.utcnow().isoformat()
            ))

    def sync_task(self, task: Task) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO tasks (id, project_id, title, description, status, priority, assignee_id, reporter_id, due_date, created_at, updated_at, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task.id, task.project_id, task.title, task.description,
                task.status.value, task.priority.value, task.assignee_id,
                task.reporter_id, task.due_date.isoformat() if task.due_date else None,
                task.created_at.isoformat(), task.updated_at.isoformat(),
                datetime.utcnow().isoformat()
            ))

    def sync_user(self, user: User) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO users (id, email, name, avatar_url, created_at, updated_at, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user.id, user.email, user.name, str(user.avatar_url) if user.avatar_url else None,
                user.created_at.isoformat(), user.updated_at.isoformat(),
                datetime.utcnow().isoformat()
            ))

    def sync_comment(self, comment: Comment) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO comments (id, task_id, author_id, content, created_at, updated_at, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                comment.id, comment.task_id, comment.author_id, comment.content,
                comment.created_at.isoformat(), comment.updated_at.isoformat() if comment.updated_at else None,
                datetime.utcnow().isoformat()
            ))

    def sync_webhook(self, webhook: WebhookSubscription) -> None:
        import json
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO webhooks (id, url, events, secret, created_at, synced_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                webhook.id, str(webhook.url), json.dumps(webhook.events), webhook.secret,
                webhook.created_at.isoformat(), datetime.utcnow().isoformat()
            ))

    def get_task_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]

    def get_project_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row:
                return User(
                    id=row["id"], email=row["email"], name=row["name"],
                    avatar_url=row["avatar_url"], created_at=datetime.fromisoformat(row["created_at"]),
                    updated_at=datetime.fromisoformat(row["updated_at"])
                )
            return None

    def get_task_by_id(self, task_id: str) -> Optional[Task]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row:
                from task_sync.models import TaskStatus, Priority
                return Task(
                    id=row["id"], project_id=row["project_id"], title=row["title"],
                    description=row["description"], status=TaskStatus(row["status"]),
                    priority=Priority(row["priority"]), assignee_id=row["assignee_id"],
                    reporter_id=row["reporter_id"], due_date=datetime.fromisoformat(row["due_date"]) if row["due_date"] else None,
                    created_at=datetime.fromisoformat(row["created_at"]), updated_at=datetime.fromisoformat(row["updated_at"])
                )
            return None