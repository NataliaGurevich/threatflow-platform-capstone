#!/usr/bin/env bash
set -euo pipefail
airflow db migrate
airflow pools set nvd_api_pool 1 'NVD API requests'
airflow pools set cisa_api_pool 1 'CISA API requests'
airflow pools set epss_api_pool 1 'EPSS API requests'
