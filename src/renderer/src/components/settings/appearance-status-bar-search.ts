import { createLocalizedCatalog } from '@/i18n/localized-catalog'
import { buildStatusBarToggleEntries } from './appearance-status-bar-search-entries'
import { buildSystemStatusBarToggleEntries } from './appearance-status-bar-system-entries'

export type { StatusBarToggleEntry } from './appearance-status-bar-search-entries'

// Why: provider usage toggles and system toggles live in separate files so each
// stays under the 300-line max-lines cap (AGENTS.md). Order is preserved:
// provider usage items first, then the system items (hosts, resources, ports).
export const getStatusBarToggles = createLocalizedCatalog(() => [
  ...buildStatusBarToggleEntries(),
  ...buildSystemStatusBarToggleEntries()
])
