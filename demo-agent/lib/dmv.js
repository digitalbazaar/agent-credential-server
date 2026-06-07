/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * A simulated CA DMV resource server for the register-a-vehicle demo. It makes
 * NO real DMV API call — registration returns what it *would* record. The DMV
 * holds the authoritative state the agent must never hold: the StatusList2021
 * revocation list for driver credentials, and the registration record store.
 *
 * Revocation is checked in memory here, against the genuine DB status-list
 * codec (decodeStatusList / isRevoked), rather than via a network fetch — so
 * the demo and its eval stay offline and deterministic. The full design is in
 * docs/dmv-demo-spec.md.
 */
import {decodeStatusList, isRevoked} from 'mcp-server/lib/core/revocation.js';
import {createList} from '@digitalbazaar/vc-status-list';

const STATUS_LIST_LENGTH = 16384;

/**
 * @typedef {object} Vehicle
 * @property {string} make - The vehicle make.
 * @property {string} model - The vehicle model.
 * @property {number} year - The model year.
 * @property {string} vin - The vehicle identification number.
 */

/**
 * @typedef {object} RevocationCheck
 * @property {boolean} revoked - Whether the credential's status bit is set.
 * @property {string} [reason] - A human-readable reason when revoked.
 */

/**
 * @typedef {object} RegistrationResult
 * @property {boolean} registered - Whether the registration was recorded.
 * @property {boolean} simulated - Always true; no real DMV call is made.
 * @property {string} [confirmation] - The simulated confirmation number.
 */

/**
 * @typedef {object} DmvServer
 * @property {(statusIndex: number) => Promise<RevocationCheck>} checkRevoked -
 *   Check a driver credential's revocation bit against the DMV status list.
 * @property {(vehicle: Vehicle) => RegistrationResult} register - Record a
 *   (simulated) vehicle registration and return a confirmation.
 */

/**
 * @typedef {object} CreateDmvServerOptions
 * @property {number[]} [revokedIndexes] - Status-list bit positions the DMV has
 *   revoked; defaults to none revoked.
 */

/**
 * Create a fresh simulated DMV resource server. The revocation list and the
 * registration store live here, in the verifier — never with the agent.
 *
 * @param {CreateDmvServerOptions} [options] - Which status bits are revoked.
 * @returns {Promise<DmvServer>} The simulated DMV server.
 */
export async function createDmvServer(options = {}) {
  const revokedIndexes = options.revokedIndexes ?? [];
  const list = await createList({length: STATUS_LIST_LENGTH});
  for(const index of revokedIndexes) {
    list.setStatus(index, true);
  }
  const encodedList = await list.encode();

  let registrationCounter = 0;

  return Object.freeze({
    async checkRevoked(/** @type {number} */ statusIndex) {
      const decoded = await decodeStatusList(encodedList);
      if(isRevoked(decoded, statusIndex)) {
        return {
          revoked: true,
          reason: `Driver credential revoked (status index ${statusIndex})`
        };
      }
      return {revoked: false};
    },

    register(/** @type {Vehicle} */ vehicle) {
      registrationCounter += 1;
      const confirmation = `CA-REG-${String(registrationCounter)
        .padStart(6, '0')}`;
      return {
        registered: true,
        simulated: true,
        confirmation,
        vehicle
      };
    }
  });
}
