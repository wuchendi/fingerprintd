CREATE TABLE `checkin_events` (
	`account_id` text NOT NULL,
	`visitor_id` text NOT NULL,
	`ip` text NOT NULL,
	`ts` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_checkin_events_visitor_ts` ON `checkin_events` (`visitor_id`,`ts`);--> statement-breakpoint
CREATE INDEX `idx_checkin_events_account_ts` ON `checkin_events` (`account_id`,`ts`);--> statement-breakpoint
CREATE INDEX `idx_checkin_events_ip_ts` ON `checkin_events` (`ip`,`ts`);--> statement-breakpoint
CREATE TABLE `blocking_index` (
	`key` text NOT NULL,
	`visitor_id` text NOT NULL,
	PRIMARY KEY(`key`, `visitor_id`)
);
--> statement-breakpoint
CREATE INDEX `idx_blocking_index_key` ON `blocking_index` (`key`);--> statement-breakpoint
CREATE TABLE `templates` (
	`visitor_id` text PRIMARY KEY NOT NULL,
	`components` text NOT NULL,
	`first_seen` integer NOT NULL,
	`last_seen` integer NOT NULL,
	`observation_count` integer NOT NULL
);
