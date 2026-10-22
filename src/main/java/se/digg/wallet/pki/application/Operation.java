// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

/** Normal reconciliation preserves keys; changing keys requires ROTATE. */
public enum Operation {
  ENSURE, RENEW, ROTATE, VERIFY
}
