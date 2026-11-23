export interface CalendarEvent {
  id: string;
  summary: string;
  startTime: string;
  endTime: string;
  location?: string;
}

export class CalendarService {
  /**
   * Lists upcoming Google Calendar events
   */
  public static async listEvents(
    timeMin?: string,
    timeMax?: string,
    accessToken?: string
  ): Promise<{ authenticated: boolean; events: CalendarEvent[]; messageText?: string }> {
    if (!accessToken) {
      return {
        authenticated: false,
        events: [],
        messageText: 'Google Calendar is not connected. Use /calendar connect to link your calendar.'
      };
    }

    const nowIso = timeMin || new Date().toISOString();
    const endIso = timeMax || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    const url = `https://www.googleapis.com/calendar/v3/calendars/primary/events?timeMin=${encodeURIComponent(nowIso)}&timeMax=${encodeURIComponent(endIso)}&singleEvents=true&orderBy=startTime`;

    try {
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(8000)
      });

      if (!resp.ok) {
        return { authenticated: false, events: [], messageText: `Calendar API error: ${resp.status}` };
      }

      const data = (await resp.json()) as any;
      const items = (data.items || []).map((ev: any) => ({
        id: ev.id,
        summary: ev.summary || '(Untitled Event)',
        startTime: ev.start?.dateTime || ev.start?.date || '',
        endTime: ev.end?.dateTime || ev.end?.date || '',
        location: ev.location
      }));

      return {
        authenticated: true,
        events: items
      };
    } catch (err: any) {
      return { authenticated: false, events: [], messageText: `Calendar error: ${err.message}` };
    }
  }

  /**
   * Detects schedule conflicts between events
   */
  public static detectConflicts(events: CalendarEvent[]): Array<{ eventA: string; eventB: string }> {
    const conflicts: Array<{ eventA: string; eventB: string }> = [];
    for (let i = 0; i < events.length; i++) {
      for (let j = i + 1; j < events.length; j++) {
        const aStart = new Date(events[i].startTime).getTime();
        const aEnd = new Date(events[i].endTime).getTime();
        const bStart = new Date(events[j].startTime).getTime();
        const bEnd = new Date(events[j].endTime).getTime();

        if (aStart < bEnd && bStart < aEnd) {
          conflicts.push({ eventA: events[i].summary, eventB: events[j].summary });
        }
      }
    }
    return conflicts;
  }
}
