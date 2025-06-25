from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sentry', '0003_alter_analysis_cost_estimate_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='stacktemplate',
            old_name='is_analyzed',
            new_name='is_analysed',
        ),
    ]
