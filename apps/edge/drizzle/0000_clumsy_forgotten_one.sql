CREATE TABLE `checkin_events` (
	`request_id` text NOT NULL,
	`account_id` text NOT NULL,
	`visitor_id` text NOT NULL,
	`ip` text NOT NULL,
	`ts` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_checkin_events_request_id` ON `checkin_events` (`request_id`);--> statement-breakpoint
CREATE INDEX `idx_checkin_events_visitor_ts` ON `checkin_events` (`visitor_id`,`ts`);--> statement-breakpoint
CREATE INDEX `idx_checkin_events_account_ts` ON `checkin_events` (`account_id`,`ts`);--> statement-breakpoint
CREATE INDEX `idx_checkin_events_ip_ts` ON `checkin_events` (`ip`,`ts`);--> statement-breakpoint
CREATE TABLE `events` (
	`request_id` text PRIMARY KEY NOT NULL,
	`visitor_id` text NOT NULL,
	`ip` text,
	`body` text NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_events_visitor_id` ON `events` (`visitor_id`);--> statement-breakpoint
CREATE INDEX `idx_events_expires_at` ON `events` (`expires_at`);--> statement-breakpoint
CREATE TABLE `blocking_index` (
	`key` text NOT NULL,
	`visitor_id` text NOT NULL,
	PRIMARY KEY(`key`, `visitor_id`)
);
--> statement-breakpoint
CREATE INDEX `idx_blocking_index_key` ON `blocking_index` (`key`);--> statement-breakpoint
CREATE INDEX `idx_blocking_index_visitor_id` ON `blocking_index` (`visitor_id`);--> statement-breakpoint
CREATE TABLE `erased_visitors` (
	`visitor_id` text PRIMARY KEY NOT NULL,
	`erased_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_erased_visitors_erased_at` ON `erased_visitors` (`erased_at`);--> statement-breakpoint
CREATE TABLE `templates` (
	`visitor_id` text PRIMARY KEY NOT NULL,
	`stored` text NOT NULL,
	`first_seen` integer NOT NULL,
	`last_seen` integer NOT NULL,
	`observation_count` integer NOT NULL
);
