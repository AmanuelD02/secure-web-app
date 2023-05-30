"""empty message

Revision ID: ced4aac7ff00
Revises: 4d9dff9be94d
Create Date: 2023-05-30 16:56:18.047948

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ced4aac7ff00'
down_revision = '4d9dff9be94d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.add_column(sa.Column('real_file_name', sa.String(length=250), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.drop_column('real_file_name')

    # ### end Alembic commands ###