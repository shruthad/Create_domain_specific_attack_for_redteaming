const MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
const TIMEOUT_MS = Number(process.env.GEMINI_TIMEOUT_MS || 60000);

class GeminiRestProvider {
  id() {
    return `gemini-rest:${MODEL}`;
  }

  async callApi(prompt) {
    const apiKey = process.env.GOOGLE_API_KEY;
    if (!apiKey) {
      return { error: 'GOOGLE_API_KEY is not set.' };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${apiKey}`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            maxOutputTokens: 256,
            temperature: 0.2,
          },
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        if (response.status === 429) {
          return {
            error: `Gemini quota exhausted or temporarily unavailable. Wait, reduce test count, or check your Google AI Studio quota. Details: ${JSON.stringify(data)}`,
          };
        }
        return {
          error: `Gemini REST HTTP ${response.status}: ${JSON.stringify(data)}`,
        };
      }

      const parts = data?.candidates?.[0]?.content?.parts || [];
      const output = parts.map((part) => part.text || '').join('').trim();
      if (!output) {
        return { error: `Gemini REST returned no text: ${JSON.stringify(data)}` };
      }
      return { output, tokenUsage: data.usageMetadata || {} };
    } catch (error) {
      const message = error?.name === 'AbortError'
        ? `Gemini REST request timed out after ${TIMEOUT_MS}ms`
        : `Gemini REST request failed: ${error?.message || String(error)}`;
      return { error: message };
    } finally {
      clearTimeout(timeout);
    }
  }
}

module.exports = GeminiRestProvider;
