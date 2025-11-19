export type NotificationChannel = 'email' | 'sms' | 'push' | 'in_app';
export type NotificationTopicCategory = 'account' | 'animals' | 'operations' | 'security' | 'system';
export type NotificationDigestFrequency = 'daily' | 'weekly';
export type NotificationDevicePlatform = 'ios' | 'android' | 'web' | 'unknown';

export type NotificationTopicPreference = {
	id: string;
	label: string;
	description?: string | null;
	category: NotificationTopicCategory;
	enabled: boolean;
	channels: NotificationChannel[];
	critical?: boolean;
	muteUntil?: string | null;
};

export type NotificationDigestSettings = {
	enabled: boolean;
	frequency: NotificationDigestFrequency;
	sendHourLocal: number;
	timezone?: string | null;
	includeSummary: boolean;
};

export type NotificationQuietHours = {
	enabled: boolean;
	startHour: number;
	endHour: number;
	timezone?: string | null;
};

export type NotificationCriticalEscalations = {
	smsFallback: boolean;
	backupEmail?: string | null;
	pagerDutyWebhook?: string | null;
};

export type NotificationDevice = {
	id: string;
	label: string;
	platform: NotificationDevicePlatform;
	enabled: boolean;
	lastUsedAt?: string | null;
};

export type NotificationSettings = {
	defaultChannels: NotificationChannel[];
	topics: NotificationTopicPreference[];
	digests: NotificationDigestSettings;
	quietHours: NotificationQuietHours;
	criticalEscalations: NotificationCriticalEscalations;
	devices: NotificationDevice[];
};

export type NotificationTopicPreferenceInput = Partial<Omit<NotificationTopicPreference, 'id'>> & { id: string };

export type NotificationSettingsInput = Partial<Omit<NotificationSettings, 'topics' | 'devices'>> & {
	topics?: NotificationTopicPreferenceInput[];
	devices?: NotificationDevice[];
};