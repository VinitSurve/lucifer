export interface DriveFileSummary {
  id: string;
  name: string;
  mimeType: string;
  modifiedTime: string;
  webViewLink?: string;
}

export class DriveService {
  /**
   * Searches documents, PDFs, sheets in Google Drive
   */
  public static async searchFiles(
    query: string,
    accessToken?: string
  ): Promise<{ authenticated: boolean; files: DriveFileSummary[]; messageText?: string }> {
    if (!accessToken) {
      return {
        authenticated: false,
        files: [],
        messageText: 'Google Drive is not connected. Use /drive connect to authorize.'
      };
    }

    const q = `name contains '${query.replace(/'/g, "\\'")}' and trashed = false`;
    const url = `https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(q)}&pageSize=10&fields=files(id,name,mimeType,modifiedTime,webViewLink)`;

    try {
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(8000)
      });

      if (!resp.ok) {
        return { authenticated: false, files: [], messageText: `Drive API error: ${resp.status}` };
      }

      const data = (await resp.json()) as any;
      const files: DriveFileSummary[] = (data.files || []).map((f: any) => ({
        id: f.id,
        name: f.name,
        mimeType: f.mimeType,
        modifiedTime: f.modifiedTime,
        webViewLink: f.webViewLink
      }));

      return { authenticated: true, files };
    } catch (err: any) {
      return { authenticated: false, files: [], messageText: `Drive error: ${err.message}` };
    }
  }
}
