# Output plugin for sending records to an Azure Service Bus Queue for [Fluentd](http://fluentd.org)

## Requirements

| fluent-plugin-record-modifier  | fluentd | ruby |
|--------------------------------|---------|------|
| >= 1.0.0 | >= v0.14.0 | >= 2.1 |
|  < 1.0.0 | >= v0.12.0 | >= 1.9 |

## Configuration

    <match ucs.**>
        @type azure_servicebus_queue
        namespace servicebusNamespace
        queueName queueName
        accessKeyName send
        accessKeyValueFile /etc/password/queuePassword
        format json
    </match>

Will send records in json format to Azure Service Bus Queue with namespace of servicebusNamespace with queue name of queueName. Will use Shared access policy named send and the Primary/Secondary key in a file located in /etc/password/queuePassword.

