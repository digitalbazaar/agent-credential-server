/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * IO boundary: fetch a StatusList2021 credential and extract the encodedList.
 */

/**
 * @param {string} url - The status list credential URL to fetch.
 * @returns {Promise<{encodedList: string | null, error?: string}>} The
 *   extracted encodedList, or null with an error message on failure.
 */
export async function fetchStatusList(url) {
  try {
    const response = await fetch(url, {headers: {Accept: 'application/json'}});
    if(!response.ok) {
      return {encodedList: null, error: `HTTP ${response.status}`};
    }

    const data = await response.json();

    // Status list may be a raw VC or a JWT-encoded VC
    // Handle JSON-LD format: data.credentialSubject.encodedList
    const subject = data.credentialSubject;
    if(subject?.encodedList) {
      return {encodedList: subject.encodedList};
    }

    // Handle VC wrapper: data.vc.credentialSubject.encodedList
    const vc = data.vc;
    if(vc?.credentialSubject?.encodedList) {
      return {encodedList: vc.credentialSubject.encodedList};
    }

    return {
      encodedList: null,
      error: 'No encodedList found in status list credential'
    };
  } catch(err) {
    return {encodedList: null, error: String(err)};
  }
}
