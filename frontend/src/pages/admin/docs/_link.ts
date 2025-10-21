// Helpers to build deep links into ReDoc using operationId and tags.
// ReDoc supports #operation/{operationId} and #tag/{tagName}
export const linkToOperation = (opId: string) => `/docs#operation/${encodeURIComponent(opId)}`
export const linkToTag = (tag: string) => `/docs#tag/${encodeURIComponent(tag)}`
