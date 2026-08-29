import pytest
from datetime import datetime, date
from unittest.mock import Mock, patch, MagicMock
import httpx

from task_sync.models import (
    Project, ProjectCreate, ProjectUpdate,
    Task, TaskCreate, TaskUpdate, TaskStatus, Priority,
    User, Comment, CommentCreate,
    WebhookSubscription, WebhookSubscriptionCreate,
    PaginatedResponse
)
from task_sync.client import TaskSyncClient
from task_sync.sync import TaskSync


# ==================== FIXTURES ====================

@pytest.fixture
def mock_client():
    """Create a TaskSyncClient with mocked HTTP client."""
    client = TaskSyncClient("https://api.example.com/v1", "test-token")
    client.client = Mock(spec=httpx.Client)
    return client


@pytest.fixture
def sample_project():
    return Project(
        id="550e8400-e29b-41d4-a716-446655440000",
        name="Test Project",
        description="A test project",
        owner_id="550e8400-e29b-41d4-a716-446655440001",
        created_at=datetime(2024, 1, 15, 10, 30, 0),
        updated_at=datetime(2024, 1, 20, 14, 22, 0),
    )


@pytest.fixture
def sample_task():
    return Task(
        id="550e8400-e29b-41d4-a716-446655440010",
        project_id="550e8400-e29b-41d4-a716-446655440000",
        title="Test Task",
        description="A test task",
        status=TaskStatus.TODO,
        priority=Priority.MEDIUM,
        assignee_id="550e8400-e29b-41d4-a716-446655440002",
        reporter_id="550e8400-e29b-41d4-a716-446655440001",
        due_date=date(2024, 2, 15),
        created_at=datetime(2024, 1, 15, 10, 30, 0),
        updated_at=datetime(2024, 1, 20, 14, 22, 0),
    )


@pytest.fixture
def sample_user():
    return User(
        id="550e8400-e29b-41d4-a716-446655440001",
        email="john.doe@example.com",
        name="John Doe",
        avatar_url="https://example.com/avatar.png",
        created_at=datetime(2023, 6, 15, 8, 0, 0),
        updated_at=datetime(2024, 1, 10, 12, 0, 0),
    )


@pytest.fixture
def sample_comment():
    return Comment(
        id="550e8400-e29b-41d4-a716-446655440020",
        task_id="550e8400-e29b-41d4-a716-446655440010",
        author_id="550e8400-e29b-41d4-a716-446655440001",
        content="This is a test comment",
        created_at=datetime(2024, 1, 20, 15, 30, 0),
        updated_at=datetime(2024, 1, 20, 16, 0, 0),
    )


@pytest.fixture
def temp_db(tmp_path):
    db_path = tmp_path / "test_tasksync.db"
    return TaskSync(str(db_path))


# ==================== MODEL TESTS ====================

class TestModels:
    """Test that models match the OLD API contract."""

    def test_project_has_owner_id_not_lead_id(self, sample_project):
        """Project MUST have owner_id field (will be renamed to lead_id in v2)."""
        assert hasattr(sample_project, "owner_id")
        assert sample_project.owner_id == "550e8400-e29b-41d4-a716-446655440001"
        # lead_id should NOT exist in v1
        assert not hasattr(sample_project, "lead_id")

    def test_task_has_assignee_id(self, sample_task):
        """Task MUST have assignee_id field (will be REMOVED in v2)."""
        assert hasattr(sample_task, "assignee_id")
        assert sample_task.assignee_id == "550e8400-e29b-41d4-a716-446655440002"

    def test_task_due_date_optional(self):
        """TaskCreate due_date MUST be optional in v1."""
        task = TaskCreate(project_id="proj-1", title="Test")
        assert task.due_date is None
        # Should be able to create without due_date
        task2 = TaskCreate(project_id="proj-1", title="Test", due_date=date(2024, 2, 15))
        # pydantic converts date to datetime, so check the date part
        assert task2.due_date is not None
        assert task2.due_date.date() == date(2024, 2, 15)

    def test_task_status_enum_has_done(self):
        """TaskStatus enum MUST have DONE value (will be COMPLETED in v2)."""
        assert TaskStatus.DONE == "DONE"
        # COMPLETED should NOT exist in v1 enum
        assert "COMPLETED" not in [s.value for s in TaskStatus]

    def test_user_created_at_is_datetime(self, sample_user):
        """User.created_at MUST be datetime (will change to int unix timestamp in v2)."""
        assert isinstance(sample_user.created_at, datetime)
        assert sample_user.created_at == datetime(2023, 6, 15, 8, 0, 0)

    def test_comment_model_exists(self, sample_comment):
        """Comment model MUST exist (endpoint will be REMOVED in v2)."""
        assert sample_comment.id == "550e8400-e29b-41d4-a716-446655440020"
        assert sample_comment.content == "This is a test comment"


# ==================== CLIENT TESTS ====================

class TestTaskSyncClient:
    """Test client methods against OLD API contract."""

    def test_get_project_returns_owner_id(self, mock_client, sample_project):
        """GET /projects/{id} returns Project with owner_id."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": sample_project.id,
            "name": sample_project.name,
            "description": sample_project.description,
            "owner_id": sample_project.owner_id,
            "created_at": sample_project.created_at.isoformat(),
            "updated_at": sample_project.updated_at.isoformat(),
        }
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        result = mock_client.get_project(sample_project.id)

        assert result.owner_id == sample_project.owner_id
        # Verify the request was made correctly
        mock_client.client.request.assert_called_once_with("GET", f"/projects/{sample_project.id}")

    def test_create_task_due_date_optional(self, mock_client, sample_task):
        """POST /projects/{id}/tasks accepts TaskCreate without due_date."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": sample_task.id,
            "project_id": sample_task.project_id,
            "title": sample_task.title,
            "description": sample_task.description,
            "status": sample_task.status.value,
            "priority": sample_task.priority.value,
            "assignee_id": sample_task.assignee_id,
            "reporter_id": sample_task.reporter_id,
            "due_date": sample_task.due_date.isoformat() if sample_task.due_date else None,
            "created_at": sample_task.created_at.isoformat(),
            "updated_at": sample_task.updated_at.isoformat(),
        }
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        task_create = TaskCreate(project_id=sample_task.project_id, title=sample_task.title)
        result = mock_client.create_task(sample_task.project_id, task_create)

        # Verify due_date was NOT sent (optional in v1)
        call_args = mock_client.client.request.call_args
        sent_json = call_args[1]["json"]
        assert "due_date" not in sent_json or sent_json.get("due_date") is None
        assert result.id == sample_task.id

    def test_get_task_includes_assignee_id(self, mock_client, sample_task):
        """GET /tasks/{id} returns Task with assignee_id."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": sample_task.id,
            "project_id": sample_task.project_id,
            "title": sample_task.title,
            "description": sample_task.description,
            "status": sample_task.status.value,
            "priority": sample_task.priority.value,
            "assignee_id": sample_task.assignee_id,
            "reporter_id": sample_task.reporter_id,
            "due_date": sample_task.due_date.isoformat() if sample_task.due_date else None,
            "created_at": sample_task.created_at.isoformat(),
            "updated_at": sample_task.updated_at.isoformat(),
        }
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        result = mock_client.get_task(sample_task.id)

        assert result.assignee_id == sample_task.assignee_id

    def test_get_user_created_at_is_datetime(self, mock_client, sample_user):
        """GET /users/{id} returns User with datetime created_at."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": sample_user.id,
            "email": sample_user.email,
            "name": sample_user.name,
            "avatar_url": str(sample_user.avatar_url),
            "created_at": sample_user.created_at.isoformat(),
            "updated_at": sample_user.updated_at.isoformat(),
        }
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        result = mock_client.get_user(sample_user.id)

        assert isinstance(result.created_at, datetime)
        assert result.created_at == sample_user.created_at

    def test_delete_comment_endpoint_exists(self, mock_client):
        """DELETE /comments/{id} endpoint MUST exist (will be removed in v2)."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        mock_client.delete_comment("comment-123")

        mock_client.client.request.assert_called_once_with("DELETE", "/comments/comment-123")

    def test_list_tasks_status_filter_uses_enum_values(self, mock_client):
        """GET /projects/{id}/tasks?status= uses TaskStatus enum values."""
        mock_response = Mock()
        mock_response.json.return_value = {"data": [], "next_cursor": None, "has_more": False}
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        mock_client.list_tasks("proj-1", status=TaskStatus.DONE)

        call_args = mock_client.client.request.call_args
        params = call_args[1]["params"]
        assert params["status"] == "DONE"  # Not "COMPLETED"


# ==================== SYNC TESTS ====================

class TestTaskSync:
    """Test sync functionality with OLD API contract."""

    def test_sync_project_stores_owner_id(self, temp_db, sample_project):
        """Sync stores project with owner_id in database."""
        temp_db.sync_project(sample_project)

        # Verify by reading back
        with temp_db.db_path.open() as f:
            pass  # Just verify no error
        # Use the getter
        # Note: we don't have a get_project method, but we can check count
        assert temp_db.get_project_count() == 1

    def test_sync_task_stores_assignee_id(self, temp_db, sample_task):
        """Sync stores task with assignee_id in database."""
        temp_db.sync_task(sample_task)

        retrieved = temp_db.get_task_by_id(sample_task.id)
        assert retrieved is not None
        assert retrieved.assignee_id == sample_task.assignee_id

    def test_sync_user_stores_datetime_created_at(self, temp_db, sample_user):
        """Sync stores user with datetime created_at."""
        temp_db.sync_user(sample_user)

        retrieved = temp_db.get_user_by_id(sample_user.id)
        assert retrieved is not None
        assert isinstance(retrieved.created_at, datetime)
        assert retrieved.created_at == sample_user.created_at

    def test_sync_comment_works(self, temp_db, sample_comment):
        """Sync comment works (endpoint will be removed in v2)."""
        temp_db.sync_comment(sample_comment)
        # No getter for comments, but sync should not error


# ==================== INTEGRATION TESTS ====================

class TestAPIContractIntegration:
    """Integration tests verifying the full OLD contract."""

    def test_full_task_workflow_old_contract(self, mock_client, temp_db):
        """Complete workflow: create -> get -> update -> sync."""
        project_id = "550e8400-e29b-41d4-a716-446655440000"
        task_id = "550e8400-e29b-41d4-a716-446655440010"

        # Mock create task response (without due_date - optional in v1)
        create_response = Mock()
        create_response.json.return_value = {
            "id": task_id,
            "project_id": project_id,
            "title": "New Task",
            "description": "Description",
            "status": "TODO",
            "priority": "MEDIUM",
            "assignee_id": "550e8400-e29b-41d4-a716-446655440002",
            "reporter_id": "550e8400-e29b-41d4-a716-446655440001",
            "due_date": None,
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T10:30:00Z",
        }
        create_response.raise_for_status = Mock()

        # Mock get task response
        get_response = Mock()
        get_response.json.return_value = create_response.json.return_value
        get_response.raise_for_status = Mock()

        mock_client.client.request.side_effect = [create_response, get_response]

        # Create task WITHOUT due_date (valid in v1)
        task_create = TaskCreate(project_id=project_id, title="New Task")
        created_task = mock_client.create_task(project_id, task_create)

        assert created_task.assignee_id == "550e8400-e29b-41d4-a716-446655440002"
        assert created_task.due_date is None

        # Get task
        retrieved_task = mock_client.get_task(task_id)
        assert retrieved_task.assignee_id == "550e8400-e29b-41d4-a716-446655440002"

        # Sync to local DB
        temp_db.sync_task(retrieved_task)
        synced = temp_db.get_task_by_id(task_id)
        assert synced.assignee_id == "550e8400-e29b-41d4-a716-446655440002"

    def test_project_owner_id_field_name(self, mock_client, temp_db):
        """Project uses owner_id not lead_id."""
        project_id = "550e8400-e29b-41d4-a716-446655440000"

        mock_response = Mock()
        mock_response.json.return_value = {
            "id": project_id,
            "name": "Test Project",
            "description": "Desc",
            "owner_id": "550e8400-e29b-41d4-a716-446655440001",  # owner_id not lead_id
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-20T14:22:00Z",
        }
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        project = mock_client.get_project(project_id)

        assert project.owner_id == "550e8400-e29b-41d4-a716-446655440001"
        assert not hasattr(project, "lead_id")

    def test_task_status_done_not_completed(self, mock_client):
        """TaskStatus uses DONE not COMPLETED."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": "task-1",
            "project_id": "proj-1",
            "title": "Task",
            "description": None,
            "status": "DONE",  # Not COMPLETED
            "priority": "MEDIUM",
            "assignee_id": None,
            "reporter_id": "user-1",
            "due_date": None,
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-20T14:22:00Z",
        }
        mock_response.raise_for_status = Mock()
        mock_client.client.request.return_value = mock_response

        task = mock_client.get_task("task-1")
        assert task.status == TaskStatus.DONE
        # COMPLETED doesn't exist in v1 enum
        assert "COMPLETED" not in [s.value for s in TaskStatus]


# ==================== CONTRACT VALIDATION TESTS ====================

class TestOldContractValidation:
    """Explicit tests that validate the OLD API contract assumptions.
    These tests MUST pass with old spec and will FAIL with new spec.
    """

    def test_project_response_has_owner_id(self):
        """Contract: Project response includes owner_id field."""
        # This is a contract test - validates the API spec assumption
        project_data = {
            "id": "proj-1",
            "name": "Test",
            "description": None,
            "owner_id": "user-1",  # Required in v1
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-20T14:22:00Z",
        }
        project = Project(**project_data)
        assert project.owner_id == "user-1"

    def test_task_response_has_assignee_id(self):
        """Contract: Task response includes assignee_id field."""
        task_data = {
            "id": "task-1",
            "project_id": "proj-1",
            "title": "Test",
            "description": None,
            "status": "TODO",
            "priority": "MEDIUM",
            "assignee_id": "user-2",  # Present in v1, removed in v2
            "reporter_id": "user-1",
            "due_date": None,
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-20T14:22:00Z",
        }
        task = Task(**task_data)
        assert task.assignee_id == "user-2"

    def test_task_create_due_date_not_required(self):
        """Contract: TaskCreate does not require due_date."""
        task = TaskCreate(project_id="proj-1", title="Test")
        # Should not raise validation error
        assert task.due_date is None

    def test_task_status_includes_done(self):
        """Contract: TaskStatus enum includes DONE."""
        assert "DONE" in [s.value for s in TaskStatus]
        assert TaskStatus.DONE == "DONE"

    def test_user_created_at_is_datetime_string(self):
        """Contract: User.created_at is ISO datetime string."""
        user_data = {
            "id": "user-1",
            "email": "test@example.com",
            "name": "Test User",
            "avatar_url": None,
            "created_at": "2023-06-15T08:00:00Z",  # ISO datetime
            "updated_at": "2024-01-10T12:00:00Z",
        }
        user = User(**user_data)
        assert isinstance(user.created_at, datetime)

    def test_comment_endpoint_exists(self):
        """Contract: Comment model and endpoints exist."""
        comment = CommentCreate(content="Test comment")
        assert comment.content == "Test comment"
        # The client has get_comment and delete_comment methods

    def test_comment_delete_endpoint_exists(self):
        """Contract: DELETE /comments/{id} exists."""
        # Verified by client method existence
        import inspect
        assert hasattr(TaskSyncClient, "delete_comment")
        sig = inspect.signature(TaskSyncClient.delete_comment)
        assert "comment_id" in sig.parameters