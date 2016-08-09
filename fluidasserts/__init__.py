import yaml
import logging.config

logging.config.dictConfig(yaml.load(open('fluidasserts/logging.yml', 'r')))
