# po0 firewall whitelist client for RouterOS 7.16+.
# Paste this file into a named /system script, or load it as documented in README.
# Each token belongs to one machine. Optional @N pins the source subnet to slot N.
{
    :local tokens {"pgnfw_REPLACE_ME"}
    :local apiBase "https://124.221.69.228/api/firewall/"
    # Bind to a local WAN IPv4 address if needed; 0.0.0.0 selects automatically.
    # This does not override policy routing: the API must be routed directly via WAN.
    :local sourceAddress "0.0.0.0"
    :local apiVRF "main"

    :local jobName [:jobname]
    :if ([:len $jobName] > 0) do={
        :if ([/system script job print count-only where script=$jobName] > 1) do={
            :error "po0fw: another instance is running"
        }
    }

    # Cache is only for quiet logs. Never skip the POST based on this cache.
    :global po0FWState
    :if ([:typeof $po0FWState] != "array") do={ :set po0FWState [:toarray ""] }

    # Exact IPv4s must match exactly; if either side is /24, compare the C block.
    # Reject malformed IPs and unsupported prefix lengths before declaring success.
    :local sameC24 do={
        :local a [:tostr $1]
        :local b [:tostr $2]
        :local subnet false
        :local slashA [:find $a "/"]
        :local slashB [:find $b "/"]
        :if ([:typeof $slashA] != "nil") do={
            :if ([:pick $a $slashA [:len $a]] != "/24") do={ :return false }
            :set a [:pick $a 0 $slashA]
            :set subnet true
        }
        :if ([:typeof $slashB] != "nil") do={
            :if ([:pick $b $slashB [:len $b]] != "/24") do={ :return false }
            :set b [:pick $b 0 $slashB]
            :set subnet true
        }
        :if (([:typeof [:toip $a]] != "ip") || ([:typeof [:toip $b]] != "ip")) do={
            :return false
        }
        :if ($a = $b) do={ :return true }
        :if (!$subnet) do={ :return false }
        :local dotA -1
        :local dotB -1
        :for i from=1 to=3 do={
            :set dotA [:find $a "." ($dotA + 1)]
            :set dotB [:find $b "." ($dotB + 1)]
        }
        :return ([:pick $a 0 $dotA] = [:pick $b 0 $dotB])
    }

    :local index 0
    :local configured 0
    :foreach item in=$tokens do={
        :set index ($index + 1)
        :local label ("po0fw #" . $index)
        :local stateKey [:tostr $index]
        :local token [:tostr $item]
        :local slot ""
        :local valid true
        :local at [:find $token "@"]
        :if ([:typeof $at] != "nil") do={
            :set slot [:pick $token ($at + 1) [:len $token]]
            :set token [:pick $token 0 $at]
            :if (!($slot ~ "^[0-9]+\$")) do={
                :set valid false
            } else={
                :set slot [:tonum $slot]
                :if ([:typeof $slot] != "num") do={ :set valid false }
            }
        }
        # This alphabet also keeps tokens safe as URL path components.
        :if ((!($token ~ "^pgnfw_[A-Za-z0-9_-]+\$")) || ($token = "pgnfw_REPLACE_ME")) do={
            :set valid false
        }

        :if (!$valid) do={
            :log warning ($label . ": invalid token or slot; check configuration")
            :set ($po0FWState->$stateKey) "invalid-config"
        } else={
            :set configured ($configured + 1)
            :local url ($apiBase . $token . "/add")
            :if ($slot != "") do={ :set url ($url . "?slot=" . $slot) }
            :local result
            :local fetched false
            :onerror fetchError in={
                :set result [/tool fetch url=$url address=("@" . $apiVRF) \
                    src-address=$sourceAddress http-method=post http-data="" \
                    http-header-field="Content-Type:application/json" \
                    check-certificate=yes \
                    duration=15s idle-timeout=10s as-value output=user]
                :set fetched true
            } do={
                # Do not log the exception or URL: fetch errors may contain the token.
                :if ([:typeof [:find [:tostr $fetchError] "403"]] != "nil") do={
                    :log warning ($label . ": HTTP 403; check token and existing pinned-slot conflict")
                } else={
                    :if ([:typeof [:find [:tostr $fetchError] "429"]] != "nil") do={
                        :log warning ($label . ": HTTP 429; retry on next scheduled run")
                    } else={
                        :log warning ($label . ": request failed; check WAN route, TLS trust and API availability")
                    }
                }
                :set ($po0FWState->$stateKey) "request-failed"
            }

            :if ($fetched) do={
                :do {
                    :if (($result->"status") != "finished") do={ :error "unfinished fetch" }
                    :local data [:deserialize from=json value=($result->"data") options=json.no-string-conversion]
                    :local currentIp [:tostr ($data->"currentIp")]
                    :local whitelist ($data->"whitelist")
                    :local limit ($data->"limit")
                    :if (([:typeof $data] != "array") || ([:typeof ($data->"enabled")] != "bool") || \
                        ([:typeof $whitelist] != "array") || ([:typeof $limit] != "num")) do={
                        :error "invalid response shape"
                    }
                    :if (![$sameC24 $currentIp $currentIp]) do={ :error "invalid currentIp" }
                    :local applied false
                    :foreach entry in=$whitelist do={
                        :local ip [:tostr $entry]
                        :local pinnedOK ($slot = "")
                        :if ([:typeof $entry] = "array") do={
                            :set ip [:tostr ($entry->"ip")]
                            :if ($slot != "") do={ :set pinnedOK (($entry->"slot") = $slot) }
                        }
                        :if (([$sameC24 $ip $currentIp]) && $pinnedOK) do={ :set applied true }
                    }

                    :if (($data->"enabled") = false) do={
                        :log warning ($label . ": firewall is disabled")
                        :set ($po0FWState->$stateKey) "disabled"
                    } else={
                        :if (!$applied) do={
                            :log warning ($label . ": current subnet or requested slot absent from whitelist; retry next run")
                            :set ($po0FWState->$stateKey) "not-applied"
                        } else={
                            :local used [:len $whitelist]
                            :local summary ($currentIp . "|" . $used . "|" . $limit . "|" . $slot)
                            :if (($po0FWState->$stateKey) != $summary) do={
                                :local pin ""
                                :if ($slot != "") do={ :set pin (", pinned slot " . $slot) }
                                :log info ($label . ": whitelist active for " . $currentIp . ", " . $used . "/" . $limit . $pin)
                            }
                            :set ($po0FWState->$stateKey) $summary
                        }
                    }
                } on-error={
                    :log warning ($label . ": invalid API response; whitelist not confirmed")
                    :set ($po0FWState->$stateKey) "invalid-response"
                }
            }
        }
    }
    :if ($configured = 0) do={ :error "po0fw: configure at least one valid token" }
}
