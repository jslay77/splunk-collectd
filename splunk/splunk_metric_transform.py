SUPPORTED_TYPES = [
    'cpu',
    'memory',
    'disk',
    'load',
    'swap',
    'df',
    'interface'
]


def format_value(collectd_value, dimension_list, splunk_metric_transform=True):
    """
    transforms collectd value into splunk format

    :param collectd_value: value sent from collectd. eg. collectd.Values(type='disk_ops',
                                                                         plugin='disk',
                                                                         plugin_instance='1-0',
                                                                         host='waitomo-ubuntu.sv.splunk.com',
                                                                         time=1504668059.904595,
                                                                         interval=60.0,
                                                                         values=[100134850L, 48026154L])
    :param dimension_list: dimensions of the metric in list format, eg. ["env=production", "location=seattle"]
    :param smart_naming: True to use smart naming functions to format metric name. default is True
    :return: constructed metric name and (un)modified dimension list
    """
    metric_type = collectd_value.plugin
    format_func = globals().get('_format_%s_metric' % metric_type)
    dimension_list_clone = dimension_list[:]
    if splunk_metric_transform and metric_type in SUPPORTED_TYPES and format_func:
        return format_func(collectd_value, dimension_list_clone)
    return _format_default_metric(collectd_value, dimension_list_clone)


def _format_disk_metric(collectd_value, dimension_list):
    """
    format disk collectd value into splunk format

    :param collectd_value: same as in splunk_metric_transform
    :param dimension_list: same as in splunk_metric_transform
    :return: formatted disk metric name. eg. "disk.time"
             updated dimension list with disk instance. eg. "location=seattle disk=dev_sda"
    """
    value_type = collectd_value.type[len('disk_'):]
    value_type_instance = '.' + collectd_value.type_instance if len(collectd_value.type_instance) else ''
    metric_name = "%s.%s%s" % (collectd_value.plugin,
                               value_type,
                               value_type_instance)
    if len(collectd_value.plugin_instance) > 0:
        dimension_list.append('disk=%s' % collectd_value.plugin_instance)
    return metric_name, dimension_list


def _format_load_metric(collectd_value, dimension_list):
    """
    format load collectd value into splunk format

    :param collectd_value: same as in splunk_metric_transform
    :param dimension_list: same as in splunk_metric_transform
    :return: formatted load metric name -- "load"
             unmodified dimension list
    """
    metric_name = collectd_value.plugin
    return metric_name, dimension_list



def _format_interface_metric(collectd_value, dimension_list):
    """
    format interface collectd value into splunk format

    :param collectd_value: same as in splunk_metric_transform
    :param dimension_list: same as in splunk_metric_transform
    :return: formatted interface metric name -- "interface.packets"
              updated dimension list with interface instance eg. "location=seattle interface=['p2p0']"
    """
    value_type = collectd_value.type[len('if_'):]
    type_instance = '.' + collectd_value.type_instance if len(collectd_value.type_instance) else ''
    metric_name = "%s.%s%s" % (collectd_value.plugin,
                               value_type,
                               type_instance)
    if len(collectd_value.plugin_instance) > 0:
        dimension_list.append('interface=%s' % collectd_value.plugin_instance)
    return metric_name, dimension_list


def _format_cpu_metric(collectd_value, dimension_list):
    """
    format cpu collectd value into splunk format

    :param collectd_value: same as in splunk_metric_transform
    :param dimension_list: same as in splunk_metric_transform
    :return: formatted cpu metric name -- "cpu"
             unmodified dimension list
    """
    metric_name = collectd_value.plugin + '.' + collectd_value.type_instance
    if len(collectd_value.plugin_instance) > 0:
        dimension_list.append('cpu=%s' % collectd_value.plugin_instance)
    return metric_name, dimension_list


def _format_memory_metric(collectd_value, dimension_list):
    """
    format memory collectd value into splunk format

    :param collectd_value: same as in splunk_metric_transform
    :param dimension_list: same as in splunk_metric_transform
    :return: formatted memory metric name -- "memory"
             unmodified dimension list
    """
    metric_name = collectd_value.plugin + '.' + collectd_value.type_instance
    return metric_name, dimension_list


def _format_default_metric(collectd_value, dimension_list):
    """
    format collectd value into default format

    :param collectd_value: same as in splunk_metric_transform
    :param dimension_list: same as in splunk_metric_transform
    :return: formatted load metric name. eg. "disk.dev_sda.time"
             unmodified dimension list
    """
    plugin_instance = '.' + collectd_value.plugin_instance if len(collectd_value.plugin_instance) > 0 else ''
    value_type_instance = '.' + collectd_value.type_instance if len(collectd_value.type_instance) > 0 else ''
    metric_name = "%s%s.%s%s" % (collectd_value.plugin,
                                 plugin_instance,
                                 collectd_value.type,
                                 value_type_instance)
    return metric_name, dimension_list
