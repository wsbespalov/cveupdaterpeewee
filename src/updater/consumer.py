import pika

connection = pika.BlockingConnection(pika.ConnectionParameters(
        host='localhost'))
channel = connection.channel()

channel.queue_declare(queue='create')
channel.queue_declare(queue='update')

print(' [*] Waiting for messages. To exit press CTRL+C')


def create_callback(ch, method, properties, body):
    print(" [x] Received from create chanel: %r" % (body))


def update_callback(ch, method, properties, body):
    print(" [x] Received from update chanel: %r" % (body))


channel.basic_consume(create_callback,
                      queue='create',
                      no_ack=True)

channel.basic_consume(update_callback,
                      queue='update',
                      no_ack=True)

channel.start_consuming()
