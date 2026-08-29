from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl


class TaskStatus(str, Enum):
    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    IN_REVIEW = "IN_REVIEW"
    DONE = "DONE"


class Priority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    URGENT = "URGENT"


class Project(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    owner_id: str  # This field will be renamed to lead_id in new API
    created_at: datetime
    updated_at: datetime


class ProjectCreate(BaseModel):
    name: str = Field(max_length=200)
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None


class Task(BaseModel):
    id: str
    project_id: str
    title: str
    description: Optional[str] = None
    status: TaskStatus
    priority: Priority
    assignee_id: Optional[str] = None  # This field will be REMOVED in new API
    reporter_id: str
    due_date: Optional[datetime] = None  # This will become REQUIRED on create
    created_at: datetime
    updated_at: datetime


class TaskCreate(BaseModel):
    project_id: str
    title: str = Field(max_length=500)
    description: Optional[str] = None
    status: TaskStatus = TaskStatus.TODO
    priority: Priority = Priority.MEDIUM
    assignee_id: Optional[str] = None  # Will be removed
    due_date: Optional[datetime] = None  # Will become required


class TaskUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=500)
    description: Optional[str] = None
    status: Optional[TaskStatus] = None
    priority: Optional[Priority] = None
    assignee_id: Optional[str] = None  # Will be removed
    due_date: Optional[datetime] = None


class User(BaseModel):
    id: str
    email: str
    name: str
    avatar_url: Optional[HttpUrl] = None
    created_at: datetime  # Will change from datetime to int (unix timestamp)
    updated_at: datetime


class Comment(BaseModel):
    id: str
    task_id: str
    author_id: str
    content: str
    created_at: datetime
    updated_at: Optional[datetime] = None


class CommentCreate(BaseModel):
    content: str = Field(max_length=5000)


class WebhookSubscription(BaseModel):
    id: str
    url: HttpUrl
    events: list[str]
    secret: Optional[str] = None
    created_at: datetime


class WebhookSubscriptionCreate(BaseModel):
    url: HttpUrl
    events: list[str]
    secret: Optional[str] = None


class PaginatedResponse(BaseModel):
    data: list
    next_cursor: Optional[str] = None
    has_more: bool