"""Default-deny bulk permission and distinguish imported tasks."""
from alembic import op
import sqlalchemy as sa
revision='c19d0140ab21'
down_revision='7e981391de22'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('users',sa.Column('bulk_allowed',sa.Boolean(),nullable=False,server_default=sa.false()))
    op.add_column('jobs',sa.Column('kind',sa.String(10),nullable=False,server_default='single'))
    op.execute("UPDATE jobs SET kind='bulk' WHERE total>1 OR import_info<>''")
    # Existing operators need an explicit admin grant after upgrade.
    op.execute("UPDATE jobs SET state='paused', message='Weryfikacja masowa wymaga zgody administratora' WHERE kind='bulk' AND state IN ('queued','running') AND owner_id IN (SELECT id FROM users WHERE role<>'admin')")

def downgrade():
    op.drop_column('jobs','kind')
    op.drop_column('users','bulk_allowed')
