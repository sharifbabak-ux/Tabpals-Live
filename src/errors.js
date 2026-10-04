// Error codes are stable identifiers for client-side translation; `message` is a Persian default.
export const ERRORS = {
  'bad-request': [400, 'درخواست نامعتبر است.'],
  'bad-json': [400, 'بدنهٔ درخواست JSON معتبر نیست.'],
  'invalid-field': [400, 'یکی از فیلدها نامعتبر است.'],
  unauthorized: [401, 'احراز هویت لازم است.'],
  'device-revoked': [401, 'دسترسی این دستگاه لغو شده است.'],
  forbidden: [403, 'شما اجازهٔ انجام این کار را ندارید.'],
  'not-found': [404, 'پیدا نشد.'],
  'event-not-found': [404, 'رویداد پیدا نشد.'],
  'member-not-found': [404, 'عضو پیدا نشد.'],
  'device-not-found': [404, 'دستگاه پیدا نشد.'],
  'invite-not-found': [404, 'دعوت‌نامه پیدا نشد یا نامعتبر است.'],
  'event-exists': [409, 'این رویداد قبلاً ساخته شده است.'],
  'member-exists': [409, 'این عضو قبلاً اضافه شده است.'],
  'invite-used': [409, 'این دعوت‌نامه قبلاً استفاده شده است.'],
  'member-removed': [409, 'این عضو از رویداد حذف شده است.'],
  'last-admin': [409, 'رویداد باید همیشه دست‌کم یک مدیر داشته باشد.'],
  'invite-expired': [410, 'مهلت دعوت‌نامه تمام شده است.'],
  'invite-revoked': [410, 'این دعوت‌نامه لغو شده است.'],
  'payload-too-large': [413, 'حجم درخواست بیش از حد مجاز است.'],
  'rate-limited': [429, 'تعداد درخواست‌ها زیاد است؛ کمی بعد دوباره تلاش کنید.'],
  'internal-error': [500, 'خطای داخلی سرور.'],
};

// Per-op rejection reasons (in the `rejected` list of POST ops) use these codes too.
export const OP_REASONS = {
  'bad-op': 'ساختار عملیات نامعتبر است.',
  'op-too-large': 'حجم عملیات بیش از ۶۴ کیلوبایت است.',
  'unknown-entity': 'موجودیت ناشناخته است.',
  'unknown-type': 'نوع عملیات ناشناخته است.',
  'forbidden-entity': 'فقط خزانه‌دار یا مدیر می‌تواند این داده را تغییر دهد.',
  'forbidden-profile': 'هر عضو فقط پروفایل خودش را می‌تواند تغییر دهد.',
  'forbidden-purge': 'فقط مدیر می‌تواند رویداد را پاک‌سازی کند.',
};

export class ApiError extends Error {
  constructor(code, message) {
    super(message || ERRORS[code]?.[1] || code);
    this.code = code;
    this.status = ERRORS[code]?.[0] || 500;
  }
}

export const errorBody = (code, message) => ({
  error: { code, message: message || ERRORS[code]?.[1] || ERRORS['internal-error'][1] },
});
