import { config, type Config, type Env } from "../env";

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export interface Mail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

/** Send through Resend. Returns false (and logs outside production) when no key is configured. */
export async function sendMail(env: Env, cfg: Config, mail: Mail): Promise<boolean> {
  if (!env.RESEND_API_KEY) {
    if (!cfg.isProd) console.log(`[mail:disabled] to=${mail.to} subject="${mail.subject}"\n${mail.text}`);
    return false;
  }
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: cfg.mailFrom, to: [mail.to], subject: mail.subject, text: mail.text, html: mail.html }),
    });
    if (!res.ok) console.error("mail failed", res.status, (await res.text()).slice(0, 200));
    return res.ok;
  } catch (e) {
    console.error("mail error", String(e));
    return false;
  }
}

/** Hand a message to the queue (fast response, retries). Without a queue binding it is sent in the background instead. */
export function enqueueMail(c: { env: Env; executionCtx: { waitUntil(p: Promise<unknown>): void } }, cfg: Config, mail: Mail): void {
  if (c.env.MAIL_QUEUE) {
    c.executionCtx.waitUntil(
      c.env.MAIL_QUEUE.send(mail).catch((e) => {
        console.error("queue send failed, sending directly", String(e));
        return sendMail(c.env, cfg, mail);
      }),
    );
  } else {
    c.executionCtx.waitUntil(sendMail(c.env, cfg, mail));
  }
}

/** Queue consumer: one mail per message, retried (backoff) when the provider says no. */
export async function handleMailBatch(batch: MessageBatch<Mail>, env: Env): Promise<void> {
  const cfg = config(env);
  for (const msg of batch.messages) {
    // no key configured is not an error worth retrying (local development)
    const ok = (await sendMail(env, cfg, msg.body)) || !env.RESEND_API_KEY;
    if (ok) msg.ack();
    else msg.retry({ delaySeconds: 10 * (msg.attempts ** 2) });
  }
}

const frame = (title: string, body: string, button: { label: string; url: string }) => `<!doctype html><html><body style="margin:0;background:#f6f4ef;font-family:Georgia,serif;color:#1f1d1a">
<div style="max-width:480px;margin:32px auto;background:#fff;border-radius:14px;padding:32px;border:1px solid #e6e1d6">
<h1 style="font-size:20px;margin:0 0 12px">${esc(title)}</h1><p style="font-size:15px;line-height:1.6;margin:0 0 24px">${body}</p>
<a href="${esc(button.url)}" style="display:inline-block;background:#c96442;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-family:Arial,sans-serif;font-size:15px">${esc(button.label)}</a>
<p style="font-size:12px;color:#8a8478;margin:24px 0 0;font-family:Arial,sans-serif">If the button does not work, copy this link:<br>${esc(button.url)}</p></div></body></html>`;

export function verifyMail(cfg: Config, to: string, username: string, token: string): Mail {
  const url = `${cfg.appUrl}/verify-email?token=${encodeURIComponent(token)}`;
  return {
    to,
    subject: "Verify your Auto ML email",
    text: `Hi ${username},\n\nConfirm your email address to finish setting up Auto ML:\n${url}\n\nThis link works for 24 hours. If you did not sign up, ignore this message.`,
    html: frame("Confirm your email", `Hi ${esc(username)}, confirm your address to finish setting up your Auto ML account. The link works for 24 hours.`, { label: "Verify email", url }),
  };
}

export function resetMail(cfg: Config, to: string, username: string, token: string): Mail {
  const url = `${cfg.appUrl}/reset-password?token=${encodeURIComponent(token)}`;
  return {
    to,
    subject: "Reset your Auto ML password",
    text: `Hi ${username},\n\nSomeone asked to reset your Auto ML password. Choose a new one here:\n${url}\n\nThe link works for 1 hour. If this was not you, ignore this message and your password stays the same.`,
    html: frame("Reset your password", `Hi ${esc(username)}, use the button below to choose a new password. The link works for 1 hour. If this was not you, ignore this email.`, { label: "Choose a new password", url }),
  };
}
