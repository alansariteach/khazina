const VaultStore = (() => {
  // طبقة تخزين محلية تعتمد localStorage (مدعومة بكل المتصفحات وبلا تعليق)
  // بديلة عن indexedDB.open() القديمة التي تعلّق على بعض أجهزة أندرويد.
  const STORAGE_KEY = 'ciphervault-local';
  const LOCK_DURATION_MS = 15 * 60 * 1000;
  const MAX_BACKUP_ENTRIES = 5000;

  function read() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return { config: null, entries: [] };
      const parsed = JSON.parse(raw);
      return { config: parsed.config || null, entries: Array.isArray(parsed.entries) ? parsed.entries : [] };
    } catch {
      return { config: null, entries: [] };
    }
  }

  function write(data) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  function mutate(fn) {
    // ينفّذ التعديل على نسخة من البيانات ثم يحفظها — بنفس أسلوب المعاملات السابق.
    return new Promise((resolve, reject) => {
      try {
        const data = read();
        const result = fn(data);
        write(data);
        resolve(result);
      } catch (error) {
        reject(error || new Error('Unable to access local vault storage'));
      }
    });
  }

  async function getConfig() {
    const data = read();
    const config = data.config;
    return config ? validateConfig(config) : config;
  }

  async function putConfig(config) {
    await mutate((data) => {
      data.config = { ...config, id: 'vault' };
    });
  }

  async function createVault({ salt, iterations, verifier }) {
    await putConfig({
      id: 'vault', schema: 1, salt, iterations, verifier,
      createdAt: new Date().toISOString(), failedAttempts: 0, lockUntil: 0,
    });
  }

  async function recordFailedAttempt() {
    return mutate((data) => {
      const config = validateConfig(data.config || read().config);
      const failedAttempts = (config.failedAttempts || 0) + 1;
      const lockUntil = failedAttempts >= 3 ? Date.now() + LOCK_DURATION_MS : 0;
      data.config = { ...config, failedAttempts: lockUntil ? 0 : failedAttempts, lockUntil };
      return { failedAttempts, lockUntil };
    });
  }

  async function resetFailedAttempts() {
    const config = await getConfig();
    if (config) await putConfig({ ...config, failedAttempts: 0, lockUntil: 0 });
  }

  async function completeSuccessfulUnlock() {
    return mutate((data) => {
      const config = validateConfig(data.config);
      if (config.lockUntil > Date.now()) return { locked: true, config };
      const cleared = { ...config, failedAttempts: 0, lockUntil: 0 };
      data.config = cleared;
      return { locked: false, config: cleared };
    });
  }

  async function saveBiometric(biometric) {
    const config = await getConfig();
    if (!config || !isBiometric(biometric)) throw new Error('Biometric metadata is invalid');
    await putConfig({ ...config, biometric });
  }

  async function getEntries() {
    return mutate((data) => data.entries);
  }

  async function putEntry(entry) {
    await mutate((data) => {
      let found = -1;
      for (let i = 0; i < data.entries.length; i += 1) if (data.entries[i].id === entry.id) { found = i; break; }
      if (found > -1) data.entries[found] = entry; else data.entries.push(entry);
    });
  }

  async function exportBackup() {
    const config = await getConfig();
    if (!config) throw new Error('Vault has not been configured');
    const entries = await getEntries();
    const { id, failedAttempts, lockUntil, biometric, ...backupConfig } = config;
    return { format: 'ciphervault.local-backup', version: 1, exportedAt: new Date().toISOString(), config: backupConfig, entries };
  }

  function isBase64(value) {
    return typeof value === 'string' && value.length > 0 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
  }

  function isEnvelope(value) {
    return value && value.version === 1 && typeof value.iv === 'string' && value.iv.length === 16 && isBase64(value.iv) && isBase64(value.ciphertext);
  }

  function isTimestamp(value) {
    return typeof value === 'string' && Number.isFinite(Date.parse(value));
  }

  function base64ByteLength(value) {
    try { return atob(value).length; } catch { return -1; }
  }

  function isBiometric(value) {
    return value && value.version === 1 && typeof value.credentialId === 'string' && isBase64(value.credentialId) && base64ByteLength(value.credentialId) >= 8 && base64ByteLength(value.credentialId) <= 512 && typeof value.prfSalt === 'string' && isBase64(value.prfSalt) && base64ByteLength(value.prfSalt) === 32 && isEnvelope(value.wrappedKey) && isTimestamp(value.createdAt);
  }

  function validateConfig(config) {
    if (!config || config.id !== 'vault' || config.schema !== 1 || typeof config.salt !== 'string' || config.salt.length !== 24 || !isBase64(config.salt) || !Number.isInteger(config.iterations) || config.iterations < 100000 || config.iterations > 1000000 || !isEnvelope(config.verifier) || !isTimestamp(config.createdAt) || !Number.isInteger(config.failedAttempts) || config.failedAttempts < 0 || config.failedAttempts > 2 || !Number.isFinite(config.lockUntil) || config.lockUntil < 0 || (config.biometric !== undefined && !isBiometric(config.biometric))) throw new Error('Vault configuration is invalid');
    return config;
  }

  function validateBackup(backup) {
    if (!backup || backup.format !== 'ciphervault.local-backup' || backup.version !== 1 || !backup.config || !Array.isArray(backup.entries)) throw new Error('Unsupported CipherVault backup');
    const { config } = backup;
    if ('biometric' in config || config.schema !== 1 || typeof config.salt !== 'string' || config.salt.length !== 24 || !isBase64(config.salt) || !Number.isInteger(config.iterations) || config.iterations < 100000 || config.iterations > 1000000 || !isEnvelope(config.verifier) || !isTimestamp(config.createdAt)) throw new Error('Backup encryption metadata is invalid');
    if (backup.entries.length > MAX_BACKUP_ENTRIES) throw new Error('Backup contains too many entries');
    if (!backup.entries.every((entry) => typeof entry?.id === 'string' && entry.id.length >= 8 && entry.id.length <= 128 && isTimestamp(entry.createdAt) && isTimestamp(entry.updatedAt) && isEnvelope(entry.encrypted))) throw new Error('Backup entries are invalid');
    return backup;
  }

  async function replaceFromBackup(backup) {
    const valid = validateBackup(backup);
    await mutate((data) => {
      const { schema, salt, iterations, verifier, createdAt } = valid.config;
      data.config = { id: 'vault', schema, salt, iterations, verifier, createdAt, failedAttempts: 0, lockUntil: 0 };
      data.entries = valid.entries.slice();
    });
  }

  function createEntryId() {
    return crypto.randomUUID ? crypto.randomUUID() : `entry-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  return { LOCK_DURATION_MS, MAX_BACKUP_ENTRIES, getConfig, validateConfig, createVault, recordFailedAttempt, resetFailedAttempts, completeSuccessfulUnlock, saveBiometric, getEntries, putEntry, exportBackup, validateBackup, replaceFromBackup, createEntryId };
})();