export function merge(source: any, target: any): any {
  if (Array.isArray(source) && Array.isArray(target)) {
    return [...source, ...target];
  }

  if (typeof source === "object" && typeof target === "object") {
    const merged = { ...source };
    for (const key in target) {
      if (target.hasOwnProperty(key)) {
        merged[key] = merge(source[key], target[key]);
      }
    }
    return merged;
  }

  return target !== undefined ? target : source;
}
