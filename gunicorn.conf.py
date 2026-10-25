# In-memory grants require exactly one worker. Do not increase workers or replicas.
bind = "0.0.0.0:9000"
workers = 1
worker_class = "gthread"
threads = 8
timeout = 30
graceful_timeout = 10
keepalive = 5
limit_request_line = 2048
limit_request_fields = 40
limit_request_field_size = 4096
forwarded_allow_ips = ""  # The application validates the explicitly trusted proxy itself.
accesslog = "-"
access_log_format = "%(h)s %(m)s %(U)s %(s)s %(L)s"
errorlog = "-"
worker_tmp_dir = "/tmp"
