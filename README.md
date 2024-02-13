# Assert SMTP

SMTP is boring, but omnipotent, but it's a the main way to restore passwords.

## Check your SMTP relay

For now, there is no dependencies, just a modern python runtime.

The script use ENV variables :
 * SMTP_HOST
 * SMTP_USER
 * SMTP_PASSWORD

Some modern assertions :
 * TLS all the time, direct TLS connection or pimp your connection with STARTTLS
 * Authentication must be kept simple, juste AUTH PLAIN
 * The RFC doesn't specify it, but utf8 is the de facto standard for text encoding

The script tests the 3 SMTP ports :
 * 25 should not be used for mail transfer, but for server to server communication
 * 465 is no more registered for SMTP at IANA, but it was
 * 587 is the current official port for sending mails
