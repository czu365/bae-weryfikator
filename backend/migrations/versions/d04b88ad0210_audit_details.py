"""Retain encrypted search and export details."""

from alembic import op
import sqlalchemy as sa

revision = 'd04b88ad0210'
down_revision = 'c19d0140ab21'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('audit', sa.Column('details', sa.Text(), nullable=True))
    op.add_column('searches', sa.Column('scheduled_by', sa.String(36), nullable=True))
    op.create_table(
        'audit_export_rows',
        sa.Column('audit_id', sa.String(36), sa.ForeignKey('audit.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('batch', sa.Integer(), primary_key=True),
        sa.Column('payload', sa.Text(), nullable=False),
    )


def downgrade():
    op.drop_table('audit_export_rows')
    op.drop_column('searches', 'scheduled_by')
    op.drop_column('audit', 'details')
