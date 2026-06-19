# Webhook integration guide

This guide describes the webhook behavior of Fail2Ban UI and provides practical integration patterns. For the full provider settings reference, see [alert-providers.md](alert-providers.md#webhook).

## Integration model

Fail2Ban UI sends a generic JSON payload. Some platforms accept it directly; others require a transformer or relay in between.

Example payload:

```json
{
  "event": "ban",
  "ip": "203.0.113.42",
  "jail": "sshd",
  "hostname": "edge-01",
  "country": "DE",
  "failures": "5",
  "whois": "...",
  "logs": "...",
  "timestamp": "2026-03-14T11:45:00Z"
}
```

The `event` field is `"ban"`, `"unban"`, or `"test"` (sent by the test button).

## Direct webhook examples

### ntfy

* Webhook URL: `https://ntfy.example.com/fail2ban-alerts` (the topic must be part of the URL path)
* Method: `POST`
* Optional headers:
  * `Title: Fail2Ban Alert`
  * `Priority: high`
  * `Tags: rotating_light`
  * `Authorization: Bearer <token>` (for protected instances)

### Generic internal endpoint

* Webhook URL: `https://alerts.internal.example/api/fail2ban`
* Method: `POST`
* Header example: `Authorization: Bearer <service-token>`

## Relay integrations

Some APIs do not consume the generic payload as-is. The Telegram Bot API, for example, expects `chat_id` and `text` fields. In these cases, use a relay or automation layer such as n8n, Node-RED, Make, or a small custom service.

### Option 1: n8n flow

1. In Fail2Ban UI, set the webhook URL to your n8n webhook endpoint.
2. In n8n, build the flow:
   * Trigger: a Webhook node receives the Fail2Ban UI payload.
   * Transform: a Set or Function node builds the message text.
   * Action: a Telegram node (`sendMessage`) sends it, using the bot token and chat ID.

Example message template:

```text
[Fail2Ban] {{$json.event | upperCase}}
IP: {{$json.ip}}
Jail: {{$json.jail}}
Host: {{$json.hostname}}
Country: {{$json.country}}
Time: {{$json.timestamp}}
```

### Option 2: Minimal relay service

Build a small HTTP service that:

1. Accepts the Fail2Ban UI payload.
2. Formats a concise text message.
3. Calls `https://api.telegram.org/bot<TOKEN>/sendMessage` with `chat_id` and `text`.

The same approach works for Slack, Mattermost, Teams, and Discord transformations.
