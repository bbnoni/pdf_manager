"""Added first_login field to User model

Revision ID: 9c4c22df775f
Revises: 8cd23118a899
Create Date: 2025-03-09 15:48:24.740695

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9c4c22df775f'
down_revision = '8cd23118a899'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user_table', schema=None) as batch_op:
        batch_op.add_column(sa.Column('first_login', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user_table', schema=None) as batch_op:
        batch_op.drop_column('first_login')

    # ### end Alembic commands ###
