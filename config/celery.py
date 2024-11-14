from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from django.conf import settings
from celery import shared_task,signals
# import sentry_sdk
# from sentry_sdk.integrations.celery import CeleryIntegration


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
app = Celery('config')

app.conf.enable_utc = False
app.conf.update(timezone='Asia/Kolkata')
app.config_from_object(settings, namespace='CELERY')

app.autodiscover_tasks()
# app.control.inspect().active()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')


@shared_task
def say_hello():
    print('Hello!')


# # @signals.beat_init.connect
# @signals.celeryd_init.connect
# def init_sentry(**kwargs):
#     sentry_sdk.init(
#         dsn=os.environ.get("SENTRY_PROJECT_DSN"),
#         integrations=[CeleryIntegration(monitor_beat_tasks=True)],
#     )
