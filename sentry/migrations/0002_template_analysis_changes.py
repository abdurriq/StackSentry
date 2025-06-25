from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('sentry', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='stacktemplate',
            name='is_analyzed',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='analysis',
            name='template',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='sentry.stacktemplate'),
        ),
    ]
