/**
 * Run `fn` over `items` with at most `limit` in flight; items are taken in order. `limit` may be a function:
 * it is read whenever an item could start, so a raised limit starts more items at once.
 * Rejects with the first error once the items in flight have settled, like the fixed-worker version did.
 */
export async function pool<T>(items: T[], limit: number | (() => number), fn: (item: T, index: number) => Promise<void>): Promise<void> {
  const lim = typeof limit === 'function' ? limit : () => limit;
  let next = 0;
  let active = 0;
  let failed: { error: unknown } | null = null;
  await new Promise<void>((resolve, reject) => {
    // A raised limit has nothing to wake the pool up with: look again while items are left.
    const timer = typeof limit === 'function' ? setInterval(() => pump(), 500) : null;
    const finish = () => {
      if (timer) clearInterval(timer);
      if (failed) reject(failed.error);
      else resolve();
    };
    const pump = (): void => {
      while (!failed && next < items.length && active < Math.max(1, Math.floor(lim()) || 1)) {
        const index = next++;
        active++;
        fn(items[index]!, index).then(
          () => { active--; pump(); },
          (error: unknown) => { active--; failed ??= { error }; pump(); },
        );
      }
      if (active === 0 && (failed || next >= items.length)) finish();
    };
    pump();
  });
}
