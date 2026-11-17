// LoginGuard: jeden globální Durable Object (přesné počítadlo, ne „přibližné po datacentrech“).
//
// - Omezuje pokusy o přihlášení: z jedné sítě a celkově.
//   Počítá se KAŽDÝ pokus ještě před ověřením hesla, takže ani paralelní dávka neprojde.
// - Drží náhodný klíč pro podepisování session cookie. Klíč nezávisí na hesle, takže
//   z ukradené cookie nejde heslo hádat offline. Při změně hesla se vygeneruje nový
//   klíč, tím se odhlásí všechna zařízení.

import { DurableObject } from 'cloudflare:workers';

export const LIMITS = {
  perClient: { max: 5, windowMs: 15 * 60_000 },  // 5 pokusů za 15 minut z jedné IPv4 / IPv6 sítě /64
  global: { max: 50, windowMs: 60 * 60_000 },     // 50 pokusů za hodinu ze všech adres dohromady
};

export class LoginGuard extends DurableObject {
  async #load(key) {
    return (await this.ctx.storage.get(key)) || [];
  }

  /** Zaregistruje pokus. Vrací { ok, retryAfter (s) }. */
  async attempt(client) {
    const now = Date.now();
    const ck = 'c:' + client;
    const keep = (list, w) => list.filter((t) => t > now - w.windowMs);
    const mine = keep(await this.#load(ck), LIMITS.perClient);
    const all = keep(await this.#load('global'), LIMITS.global);

    const wait = (list, w) => Math.ceil((list[0] + w.windowMs - now) / 1000);
    if (mine.length >= LIMITS.perClient.max) return { ok: false, retryAfter: wait(mine, LIMITS.perClient), scope: 'client' };
    if (all.length >= LIMITS.global.max) return { ok: false, retryAfter: wait(all, LIMITS.global), scope: 'global' };

    mine.push(now);
    all.push(now);
    await this.ctx.storage.put({ [ck]: mine, global: all });
    // úklid starých klientů jednou za čas
    if (Math.random() < 0.05) await this.#sweep(now);
    return { ok: true };
  }

  /** Úspěšné přihlášení: pokusy této sítě se vynulují. */
  async success(client) {
    await this.ctx.storage.delete('c:' + client);
  }

  async #sweep(now) {
    const entries = await this.ctx.storage.list({ prefix: 'c:' });
    const old = [...entries].filter(([, v]) => !v.length || v[v.length - 1] < now - LIMITS.perClient.windowMs).map(([k]) => k);
    if (old.length) await this.ctx.storage.delete(old.slice(0, 128));
  }

  /** Náhodný podpisový klíč pro cookie, vázaný na otisk aktuálního hesla. */
  async sessionSecret(passwordFingerprint) {
    const cur = await this.ctx.storage.get('session');
    if (cur && cur.fp === passwordFingerprint) return cur.secret;
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const secret = btoa(String.fromCharCode(...bytes));
    await this.ctx.storage.put('session', { fp: passwordFingerprint, secret });
    return secret;
  }
}
