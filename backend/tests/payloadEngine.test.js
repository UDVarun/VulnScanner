const { getPayloads, getAllTypes } = require('../engines/payloadEngine');

describe('Payload Engine', () => {
  test('should return payload lists for valid types', () => {
    const list = getPayloads('SQL Injection');
    expect(list).toBeInstanceOf(Array);
    expect(list.length).toBeGreaterThan(0);
    expect(list[0]).toHaveProperty('value');
    expect(list[0]).toHaveProperty('description');
  });

  test('should return empty array for invalid type', () => {
    const list = getPayloads('NonExistentType');
    expect(list).toEqual([]);
  });

  test('should list all available payload types', () => {
    const types = getAllTypes();
    expect(types).toContain('SQL Injection');
    expect(types).toContain('XSS');
    expect(types).toContain('Header Injection');
    expect(types).toContain('Path Traversal');
  });
});
