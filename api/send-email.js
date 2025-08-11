
// Helper: simple field sanitizer
const clean = (v) => (typeof v === 'string' ? v.trim().slice(0, 5000) : '');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Basic origin check (optional)
  const allowedOrigins = [
    process.env.SITE_ORIGIN,                    // e.g. https://rajapaksaelectricals.vercel.app
    process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null
  ].filter(Boolean);

  const origin = req.headers.origin;
  if (allowedOrigins.length && origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Forbidden origin' });
  }

  // Parse body
  const { from_name, reply_to, mobile, subject, message, time, company } = req.body || {};

  // Honeypot
  if (company) {
    return res.status(200).json({ success: true });
  }

  // Validate
  if (!from_name || !reply_to || !subject || !message) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const payload = {
    from_name: clean(from_name),
    reply_to: clean(reply_to),
    mobile: clean(mobile || ''),
    subject: clean(subject),
    message: clean(message),
    time: clean(time || new Date().toISOString())
  };

  const SERVICE_ID = process.env.EMAILJS_SERVICE_ID;
  const TEMPLATE_ID = process.env.EMAILJS_TEMPLATE_ID;
  const PUBLIC_KEY  = process.env.EMAILJS_PUBLIC_KEY; // EmailJS calls this "user_id"

  if (!SERVICE_ID || !TEMPLATE_ID || !PUBLIC_KEY) {
    return res.status(500).json({ error: 'Email service not configured' });
  }

  try {
    const emailRes = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service_id: SERVICE_ID,
        template_id: TEMPLATE_ID,
        user_id: PUBLIC_KEY,
        template_params: payload
      })
    });

    if (!emailRes.ok) {
      const text = await emailRes.text().catch(() => '');
      throw new Error(`EmailJS error: ${emailRes.status} ${text}`);
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('Email send error:', err);
    return res.status(500).json({ error: 'Failed to send email' });
  }
};
