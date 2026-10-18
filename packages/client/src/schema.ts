/**
 * The closed component schema the server matches on. Keep in sync with
 * `COMPONENT_KEYS` / `Component::kind` in `crates/fp-core/src/fuzzy/component.rs`
 * (`tests/unit/schema.test.ts` asserts the key list against that file).
 *
 * Kinds: `cpu_cores` / `device_memory` are Numeric (a JSON number); `fonts` /
 * `plugins` are Sets (an array of strings); every other key is a Category (a
 * string, number or boolean). The server rejects any key outside this list.
 */

/** Every component name, in schema order. */
export const COMPONENT_KEYS = [
  'webgl',
  'webgl_extensions',
  'platform',
  'timezone',
  'languages',
  'audio',
  'canvas',
  'cpu_cores',
  'device_memory',
  'screen',
  'fonts',
  'plugins',
  'font_preferences',
  'screen_frame',
  'math',
  'touch_support',
  'dom_blockers',
  'user_agent_data',
] as const

/** A component name of the closed schema. */
export type ComponentKey = (typeof COMPONENT_KEYS)[number]

/** A Category component value. */
type Category = string | number | boolean

/** The `components` object of an identify request: every field optional,
 *  each typed by its component kind. */
export interface Components {
  webgl?: Category
  webgl_extensions?: Category
  platform?: Category
  timezone?: Category
  languages?: Category
  audio?: Category
  canvas?: Category
  cpu_cores?: number
  device_memory?: number
  screen?: Category
  fonts?: string[]
  plugins?: string[]
  font_preferences?: Category
  screen_frame?: Category
  math?: Category
  touch_support?: Category
  dom_blockers?: Category
  user_agent_data?: Category
}
