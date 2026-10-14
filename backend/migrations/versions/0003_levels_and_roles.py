"""levels 0-5 learning journey and role choice

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-14 13:30:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('learner_profiles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('desired_role', sa.String(length=40), nullable=True))
    # The journey now starts at Level 0 after choosing a role; earlier onboarding progress maps to "choose a role".
    # Passed missions and lab results are kept and count again once the learner reaches their level.
    op.execute("UPDATE learner_profiles SET onboarding_step = 'ROLE', career_level = 0, role_title = NULL, pending_promotion = NULL")


def downgrade() -> None:
    with op.batch_alter_table('learner_profiles', schema=None) as batch_op:
        batch_op.drop_column('desired_role')
