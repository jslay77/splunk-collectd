# Copyright 2017 Splunk Inc. All rights reserved.
# Environment configuration
# N/A
# Standard Python Libraries

import Queue
import json
import threading
import time
from math import isnan
import subprocess
import sys
import itertools
import collectd
from platform import uname
from socket import gethostbyname, gethostname

from splunk_metric_transform import format_value

CURRENT_OS = sys.platform

if CURRENT_OS != 'darwin':
    # Third-Party Libraries
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

CONFIG = {
    'ssl': True,
    'verify_ssl': False,
    'queue_size': 8192,
    'batch_size': 1024,
    'timeout': 60,
    'disable_ssl_warning': True,
    'splunk_metric_transform': True
}
DIMENSION_LIST_KEY = 'DIMENSION_LIST_KEY'

def _verify_configurations():
    """
    Three required configurations: server, port, token
    """
    c1 = CONFIG['server'] is not None
    c2 = CONFIG['port'] is not None
    c3 = CONFIG['token'] is not None
    return c1 and c2 and c3


def _build_splunk_metrics(value):
    # get dimension from config
    dimension_list = CONFIG.get(DIMENSION_LIST_KEY, [])

    # get name of data source
    append_names = ['.' + append_name if append_name != 'value' else ''
                    for (append_name, _, _, _)
                    in collectd.get_dataset(value.type)]
    if len(append_names) != len(value.values):
        collectd.error("len(ds_names) != len(value.values)")
        return

    # format metric name & dimension list
    # make sure you are passing a copy of dimension list
    metric_name, dimension_list = format_value(value, dimension_list, CONFIG['splunk_metric_transform'])

    # build splunk metrics data
    metrics = (dict(event=("%f metric_name=%s metric_type=%s _value=%d host=%s %s" %
                           (value.time, metric_name + postfix, value.plugin,
                            metric_value, value.host, ' '.join(dimension_list))).strip(),
                    fields=dict(metric_name=metric_name + postfix, metric_type=value.plugin, _value=metric_value))
               for (postfix, metric_value)
               in itertools.izip(append_names, value.values) if not isnan(metric_value))

    # add dimensions to fields
    dims = {}
    if dimension_list:
        arr = [x.strip() for x in dimension_list]
        for d in arr:
            (k, v) = d.split('=')
            dims.setdefault(k, []).append(v)

    for m in metrics:
        m['fields'].update(dims)
        yield m


def _send_data(config):
    protocol = 'http'
    if config['ssl'] is True:
        protocol = 'https'

    server_uri = '%s://%s:%s/services/collector' % (
        protocol, config['server'], config['port'])

    headers = ('Authorization: Splunk ' + config['token']
               if CURRENT_OS == 'darwin'
               else {'Authorization': 'Splunk ' + config['token']})
    metrics = []
    while True:
        if not metrics:
            count = 0
            start = time.time()
            timeout = config['timeout']/2
            while (time.time() - start <= timeout) and count < config['batch_size']:
                # ITOA-8109: Queue api comes with condition/lock menchanism that handles the
                # case when queue is empty. If queue is empty then it puts this resource to waiting.
                # this way we are not in a infinite loop.
                # source: https://hg.python.org/cpython/file/3a1db0d2747e/Lib/Queue.py#l150
                try:
                    value = config['metric_queue'].get(timeout=timeout)
                    new_metrics = _build_splunk_metrics(value)
                    for m in new_metrics:
                        metrics.append(json.dumps(m))
                        count += 1
                except Queue.Empty:
                    pass

        # If there is message in queue
        try:
            payload = ''.join(metrics)
            collectd.info("payload data to be sent to Splunk: {}".format(payload))
            if config['verify_ssl'] is False:
                if CURRENT_OS == 'darwin':
                    args = ['curl', '-k', server_uri, '-H', headers, '-d', payload]
                    process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                else:
                    response = requests.post(server_uri, data=payload, headers=headers, verify=False)
                    if response.status_code != requests.codes.ok:
                        collectd.error('Failed sending metrics to Splunk. Response code:{}, response content:{}'.format(
                                     response.status_code, response.content))

            else:
                if CURRENT_OS == 'darwin':
                    args = ['curl', '-k', '--cert', config['cert_file'], server_uri, '-H', headers, '-d', payload]
                    process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                else:
                    response = requests.post(server_uri, data=payload, headers=headers, verify=config['cert_file'])
                    if response.status_code != requests.codes.ok:
                        collectd.error('Failed sending metric to Splunk. Response code:{}, response content:{}'.format(
                                     response.status_code, response.content))

            if config['disable_ssl_warning'] and CURRENT_OS != 'darwin':
                requests.packages.urllib3.disable_warnings(
                    InsecureRequestWarning)
                config['disable_ssl_warning'] = False
        except Exception, e:
            collectd.error('Failed sending metric to Splunk HEC: {}'.format(str(e)))
            # Try again in 3 seconds
            time.sleep(3)

        metrics = []


def configure_callback(conf):
    """
    Configuration callback. These are accepted configs:
    Server: hostname or ip adresss
    Port: HEC port
    Token: HEC token
    QueueSize: Number, maximum metrics buffer
    SSL: true to use HTTPS
    VerifySSL: True to enable SSL verification
    CertFile: Public key of the signing authority
    Dimension: specify dimension for metrics
      i.e.  Dimension "location:phoenix"
            Dimension "type:dev"
    SplunkMetricTransform: true to use Splunk metric format
    :param conf: configration tree
    """
    dimension_list = []
    for node in conf.children:
        config_key = node.key.lower()
        if config_key == 'server':
            CONFIG['server'] = node.values[0]
        elif config_key == 'port':
            try:
                CONFIG['port'] = int(node.values[0])
            except Exception:
                collectd.error('Invalid type of Port, number is required.')
        elif config_key == 'token':
            CONFIG['token'] = node.values[0]
        elif config_key == 'ssl':
            ssl_val = node.values[0]
            if ssl_val in ['1', 'True']:
                CONFIG['ssl'] = True
            elif ssl_val in ['0', 'False']:
                CONFIG['ssl'] = False
            else:
                collectd.error('Invalid type of ssl, boolean is required.')
        elif config_key == 'verifyssl':
            ssl_val = node.values[0]
            if ssl_val in ['1', 'True']:
                CONFIG['verify_ssl'] = True
            elif ssl_val in ['0', 'False']:
                CONFIG['verify_ssl'] = False
            else:
                collectd.error('Invalid type of ssl, boolean is required.')
        elif config_key == 'queuesize':
            try:
                queue_size = int(node.values[0])
                CONFIG['queue_size'] = queue_size
            except Exception:
                collectd.error(
                    'Invalid type of queue size, number is required.')
        elif config_key == 'batchsize':
            try:
                batch_size = int(node.values[0])
                CONFIG['batch_size'] = batch_size
            except Exception:
                collectd.error(
                    'Invalid type of batch size, number is required.')
        elif config_key == 'certfile':
            CONFIG['cert_file'] = node.values[0]
        elif config_key == 'dimension':
            # if dimension value is empty, we continue
            if (len(node.values) == 0):
                collectd.error(
                    "Dimension value is empty"
                )
                continue

            try:
                (key, value) = node.values[0].split(':')
            except ValueError:
                collectd.error(
                    "Invalid dimension values: %s" % (node.values))
                continue
            dimension_list.append('%s=%s' % ((key, value)))
        elif config_key == 'splunkmetrictransform':
            should_transform = node.values[0]
            if should_transform in ['1', 'True']:
                CONFIG['splunk_metric_transform'] = True
            elif should_transform in ['0', 'False']:
                CONFIG['splunk_metric_transform'] = False
            else:
                collectd.error('Invalid type of splunk metric transform, boolean is required')
        else:
            collectd.error('Not supported config key: %s' % (config_key))

    CONFIG[DIMENSION_LIST_KEY] = dimension_list
    collectd.info("Setting configuration completed.")
    collectd.info("configuration: {}".format(CONFIG))

def _get_ip_address():
    if CURRENT_OS != 'darwin':
        return gethostbyname(gethostname())
    else:
        process = subprocess.Popen(['ipconfig', 'getifaddr', 'en0'],
                                   shell=False, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        ip_address_info, error = process.communicate()
        return ip_address_info.strip().split(' ')[0]


def init_callback():
    """
    Initialization callback. Where we start a deamon thread to send data
    """
    CONFIG['metric_queue'] = Queue.Queue(CONFIG['queue_size'])

    try:
        (system, node, release, version, machine, processor) = uname()

        dimensions = CONFIG.get(DIMENSION_LIST_KEY, [])
        # add host asset info
        dimensions.append('os=%s' % system)
        dimensions.append('os_version=%s' % release)
        # add ip address information
        dimensions.append('ip=%s' % _get_ip_address())
    except Exception as e:
        collectd.error('Unable to collect host information: %s' % e)

    if _verify_configurations() is False:
        collectd.error('Invalid configuration. Agent cannot be initialized.')
        return

    sender = threading.Thread(target=_send_data, kwargs={'config': CONFIG})
    sender.setDaemon(True)
    sender.start()


def write_callback(value):
    """
    Write callback - where data from plugins get sent
    :param value: metrics value
    """
    # put handles the case when the queue is full and calls wait on this resource and also
    # notifies the waiting _send_data to continue.
    CONFIG['metric_queue'].put(value)


collectd.register_config(configure_callback)
collectd.register_init(init_callback)
collectd.register_write(write_callback)
