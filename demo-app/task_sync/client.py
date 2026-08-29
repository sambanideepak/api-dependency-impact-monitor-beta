from datetime import datetime
from typing import Optional
import httpx
from pydantic import HttpUrl

from task_sync.models import (
    Project, ProjectCreate, ProjectUpdate,
    Task, TaskCreate, TaskUpdate, TaskStatus, Priority,
    User, Comment, CommentCreate,
    WebhookSubscription, WebhookSubscriptionCreate,
    PaginatedResponse
)


class TaskSyncClient:
    """Client for Task Management API v1."""

    def __init__(self, base_url: str, api_token: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=timeout,
        )

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        response = self.client.request(method, path, **kwargs)
        response.raise_for_status()
        return response

    # Project operations
    def list_projects(self, cursor: Optional[str] = None, limit: int = 20) -> PaginatedResponse:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        response = self._request("GET", "/projects", params=params)
        return PaginatedResponse(**response.json())

    def get_project(self, project_id: str) -> Project:
        response = self._request("GET", f"/projects/{project_id}")
        return Project(**response.json())

    def create_project(self, project: ProjectCreate) -> Project:
        response = self._request("POST", "/projects", json=project.model_dump())
        return Project(**response.json())

    def update_project(self, project_id: str, project: ProjectUpdate) -> Project:
        response = self._request("PATCH", f"/projects/{project_id}", json=project.model_dump(exclude_unset=True))
        return Project(**response.json())

    def delete_project(self, project_id: str) -> None:
        self._request("DELETE", f"/projects/{project_id}")

    # Task operations
    def list_tasks(self, project_id: str, cursor: Optional[str] = None, limit: int = 20, status: Optional[TaskStatus] = None) -> PaginatedResponse:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        if status:
            params["status"] = status.value
        response = self._request("GET", f"/projects/{project_id}/tasks", params=params)
        return PaginatedResponse(**response.json())

    def get_task(self, task_id: str) -> Task:
        response = self._request("GET", f"/tasks/{task_id}")
        return Task(**response.json())

    def create_task(self, project_id: str, task: TaskCreate) -> Task:
        # Note: due_date is optional in v1, required in v2
        response = self._request("POST", f"/projects/{project_id}/tasks", json=task.model_dump(exclude_unset=True))
        return Task(**response.json())

    def update_task(self, task_id: str, task: TaskUpdate) -> Task:
        response = self._request("PATCH", f"/tasks/{task_id}", json=task.model_dump(exclude_unset=True))
        return Task(**response.json())

    def delete_task(self, task_id: str) -> None:
        self._request("DELETE", f"/tasks/{task_id}")

    # User operations
    def get_user(self, user_id: str) -> User:
        response = self._request("GET", f"/users/{user_id}")
        return User(**response.json())

    # Comment operations
    def list_comments(self, task_id: str, cursor: Optional[str] = None, limit: int = 20) -> PaginatedResponse:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        response = self._request("GET", f"/tasks/{task_id}/comments", params=params)
        return PaginatedResponse(**response.json())

    def create_comment(self, task_id: str, comment: CommentCreate) -> Comment:
        response = self._request("POST", f"/tasks/{task_id}/comments", json=comment.model_dump())
        return Comment(**response.json())

    def get_comment(self, comment_id: str) -> Comment:
        response = self._request("GET", f"/comments/{comment_id}")
        return Comment(**response.json())

    def delete_comment(self, comment_id: str) -> None:
        self._request("DELETE", f"/comments/{comment_id}")

    # Webhook operations
    def list_webhooks(self) -> list[WebhookSubscription]:
        response = self._request("GET", "/webhooks")
        return [WebhookSubscription(**w) for w in response.json()]

    def create_webhook(self, webhook: WebhookSubscriptionCreate) -> WebhookSubscription:
        response = self._request("POST", "/webhooks", json=webhook.model_dump())
        return WebhookSubscription(**response.json())

    def delete_webhook(self, webhook_id: str) -> None:
        self._request("DELETE", f"/webhooks/{webhook_id}")

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()