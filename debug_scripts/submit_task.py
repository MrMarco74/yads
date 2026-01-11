from celery import Celery; app = Celery('yads_worker', broker='redis://redis:6379/0'); app.send_task('yads.worker.run_all_scans', args=[1, 'test.com', ['dns_scanner']])
