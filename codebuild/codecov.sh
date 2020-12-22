#/bin/bash
# https://docs.codecov.io/docs/about-the-codecov-bash-uploader
bash <(curl -s https://codecov.io/bash) -t $CODECOV_TOKEN
