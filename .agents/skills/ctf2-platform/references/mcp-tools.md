# CTF2 MCP Tools Reference

Standard Streamable HTTP MCP URL: `https://ctf2.dasctf.com/api/ai/v1/mcp`. Connect it with the client's remote HTTP/OAuth flow. Do not add an Authorization header containing a PAT to checked-in configuration.

The old `/metadata/`, `/tools/`, and `/tools/call/` REST wrappers are deprecated compatibility endpoints, not the primary MCP transport.

## `ctf2_get_profile`

Read current profile.

Required scopes: `profile:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "profile": {
      "additionalProperties": false,
      "properties": {
        "avatar": {},
        "bio": {},
        "created_at": {},
        "friendly_id": {},
        "id": {},
        "invisible_mode": {},
        "role": {},
        "updated_at": {},
        "username": {}
      },
      "type": "object"
    }
  },
  "required": [
    "profile"
  ],
  "type": "object"
}
```

## `ctf2_update_profile`

Update current profile username, avatar, bio, or invisible mode.

Required scopes: `profile:write`.

Input schema:

```json
{
  "additionalProperties": false,
  "minProperties": 1,
  "properties": {
    "avatar": {
      "maxLength": 2048,
      "type": "string"
    },
    "bio": {
      "maxLength": 500,
      "type": "string"
    },
    "invisible_mode": {
      "type": "boolean"
    },
    "username": {
      "maxLength": 20,
      "minLength": 2,
      "type": "string"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "profile": {
      "additionalProperties": false,
      "properties": {
        "avatar": {},
        "bio": {},
        "created_at": {},
        "friendly_id": {},
        "id": {},
        "invisible_mode": {},
        "role": {},
        "updated_at": {},
        "username": {}
      },
      "type": "object"
    }
  },
  "required": [
    "profile"
  ],
  "type": "object"
}
```

## `ctf2_user_get_announcements`

List active announcements.

Required scopes: `profile:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_list_platform_update_logs`

List published platform update logs.

Required scopes: `platform:update:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_list_daily_challenges`

List visible daily challenges.

Required scopes: `daily:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_list_practice_grounds`

List visible public practice grounds.

Required scopes: `practice:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "search": {
      "maxLength": 200,
      "type": "string"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_get_practice_challenge`

Read an authorized practice challenge and current suite progress.

Required scopes: `practice:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "challenge_id": {
      "format": "uuid",
      "type": "string"
    },
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "practice_ground_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "practice_ground_id",
    "challenge_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "challenge": {
      "additionalProperties": false,
      "properties": {
        "allows_multiple_flag_submissions": {
          "type": "boolean"
        },
        "category": {},
        "created_at": {},
        "description": {},
        "difficulty": {},
        "earned_points": {
          "minimum": 0,
          "type": "integer"
        },
        "files": {},
        "flag_completion_mode": {
          "enum": [
            "any",
            "all"
          ],
          "type": "string"
        },
        "friendly_id": {},
        "has_container": {},
        "id": {},
        "is_solved": {},
        "is_visible": {},
        "max_attempts": {},
        "name": {},
        "points": {},
        "practice_ground_id": {},
        "requires_running_target_for_submit": {},
        "solve_count": {},
        "solved_sub_flag_count": {
          "minimum": 0,
          "type": "integer"
        },
        "sort_order": {},
        "sub_flag_count": {
          "minimum": 0,
          "type": "integer"
        },
        "sub_flags": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "description": {
                "type": "string"
              },
              "earned_points": {
                "minimum": 0,
                "type": "integer"
              },
              "id": {
                "format": "uuid",
                "type": "string"
              },
              "index": {
                "minimum": 1,
                "type": "integer"
              },
              "is_solved": {
                "type": "boolean"
              },
              "points": {
                "minimum": 0,
                "type": "integer"
              }
            },
            "required": [
              "index",
              "points",
              "is_solved",
              "earned_points"
            ],
            "type": "object"
          },
          "type": [
            "array",
            "null"
          ]
        },
        "template_id": {},
        "total_sub_flag_count": {
          "minimum": 0,
          "type": "integer"
        },
        "translations": {},
        "updated_at": {}
      },
      "type": "object"
    }
  },
  "required": [
    "challenge"
  ],
  "type": "object"
}
```

## `ctf2_submit_flag`

Submit a confirmed practice flag; suites require a stable sub_flag_id from challenge details.

Required scopes: `practice:submit`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "challenge_id": {
      "format": "uuid",
      "type": "string"
    },
    "confirmation": {
      "const": true,
      "type": "boolean"
    },
    "flag": {
      "maxLength": 4096,
      "minLength": 1,
      "type": "string"
    },
    "practice_ground_id": {
      "format": "uuid",
      "type": "string"
    },
    "risk_challenge_answer": {
      "maxLength": 1024,
      "type": "string"
    },
    "risk_challenge_id": {
      "maxLength": 128,
      "type": "string"
    },
    "sub_flag_id": {
      "description": "Required for all-completion suites; use the stable id returned in sub_flags. Never use a display index.",
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "flag",
    "confirmation",
    "practice_ground_id",
    "challenge_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "accepted": {
      "type": "boolean"
    },
    "attempt": {
      "minimum": 1,
      "type": "integer"
    },
    "earned_points": {
      "minimum": 0,
      "type": "integer"
    },
    "is_solved": {
      "type": "boolean"
    },
    "points": {
      "type": "integer"
    },
    "solved_sub_flag_count": {
      "minimum": 0,
      "type": "integer"
    },
    "submission_id": {
      "format": "uuid",
      "type": "string"
    },
    "total_sub_flag_count": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "accepted",
    "points",
    "submission_id",
    "attempt"
  ],
  "type": "object"
}
```

## `ctf2_start_challenge_environment`

Start or reuse a practice environment.

Required scopes: `environment:write`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "challenge_id": {
      "format": "uuid",
      "type": "string"
    },
    "practice_ground_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "practice_ground_id",
    "challenge_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "environment": {
      "additionalProperties": false,
      "properties": {
        "access_ready": {
          "type": "boolean"
        },
        "access_type": {
          "maxLength": 64,
          "minLength": 1,
          "type": "string"
        },
        "access_url": {
          "maxLength": 4096,
          "minLength": 1,
          "type": "string"
        },
        "access_urls": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "nc_ssl": {
                "type": [
                  "boolean",
                  "null"
                ]
              },
              "type": {
                "maxLength": 64,
                "minLength": 1,
                "type": "string"
              },
              "url": {
                "maxLength": 4096,
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "url",
              "type"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "created_at": {
          "format": "date-time",
          "type": "string"
        },
        "environment_id": {
          "format": "uuid",
          "type": "string"
        },
        "expires_at": {
          "format": "date-time",
          "type": [
            "string",
            "null"
          ]
        },
        "nc_ssl": {
          "type": "boolean"
        },
        "status": {
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "environment_id",
        "status",
        "access_ready",
        "created_at"
      ],
      "type": "object"
    }
  },
  "required": [
    "environment"
  ],
  "type": "object"
}
```

## `ctf2_user_delete_practice_id_challenges_challengeid_environment`

Destroy the current practice environment.

Required scopes: `environment:write`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "challenge_id": {
      "format": "uuid",
      "type": "string"
    },
    "practice_ground_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "practice_ground_id",
    "challenge_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "environment": {
      "additionalProperties": false,
      "properties": {
        "environment_id": {
          "format": "uuid",
          "type": "string"
        },
        "removed": {
          "const": true,
          "type": "boolean"
        },
        "status": {
          "const": "deleting",
          "type": "string"
        }
      },
      "required": [
        "environment_id",
        "status",
        "removed"
      ],
      "type": "object"
    }
  },
  "required": [
    "environment"
  ],
  "type": "object"
}
```

## `ctf2_user_get_private_practice`

List private practice grounds available to current user.

Required scopes: `practice:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_private_practice_submissions`

List private practice submissions for current user.

Required scopes: `submission:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_get_competitions`

List visible competitions.

Required scopes: `competition:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_get_competition_status`

Read competition status and stages.

Required scopes: `competition:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "competition_id": {
      "format": "uuid",
      "type": "string"
    },
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "required": [
    "competition_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "competition": {
      "additionalProperties": true,
      "type": "object"
    },
    "stages": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    }
  },
  "required": [
    "competition",
    "stages"
  ],
  "type": "object"
}
```

## `ctf2_user_get_competitions_id_teams`

List competition teams.

Required scopes: `competition:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "competition_id": {
      "format": "uuid",
      "type": "string"
    },
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "required": [
    "competition_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_competitions_id_stages`

List competition stages.

Required scopes: `competition:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "competition_id": {
      "format": "uuid",
      "type": "string"
    },
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "required": [
    "competition_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_stages_stageid`

Read a stage.

Required scopes: `competition:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "stage_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "stage_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "stage": {
      "additionalProperties": true,
      "properties": {
        "items": {
          "items": {
            "additionalProperties": true,
            "type": "object"
          },
          "type": "array"
        },
        "total": {
          "minimum": 0,
          "type": "integer"
        }
      },
      "type": "object"
    }
  },
  "required": [
    "stage"
  ],
  "type": "object"
}
```

## `ctf2_user_get_stages_stageid_challenges`

List visible stage challenges.

Required scopes: `competition:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "stage_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "stage_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_stages_stageid_submissions`

List current user submissions in a stage.

Required scopes: `submission:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "stage_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "stage_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_stages_stageid_tickets`

List current user tickets in a stage.

Required scopes: `ticket:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "stage_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "stage_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "assigned_to": {},
          "assignee": {
            "additionalProperties": false,
            "properties": {
              "avatar": {},
              "friendly_id": {},
              "id": {},
              "username": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "category": {
            "additionalProperties": false,
            "properties": {
              "created_at": {},
              "description": {},
              "friendly_id": {},
              "id": {},
              "is_active": {},
              "name": {},
              "sort_order": {},
              "updated_at": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "category_id": {},
          "closed_at": {},
          "content": {},
          "created_at": {},
          "files": {
            "items": {
              "additionalProperties": false,
              "properties": {
                "cleanup_status": {},
                "created_at": {},
                "download_url": {},
                "expires_at": {},
                "file_type": {},
                "friendly_id": {},
                "id": {},
                "markdown_url": {},
                "mime_type": {},
                "moderation_preview_url": {},
                "moderation_status": {},
                "original_name": {},
                "pending_review_id": {},
                "size": {},
                "updated_at": {},
                "uploaded_by": {},
                "url": {},
                "user": {
                  "additionalProperties": false,
                  "properties": {
                    "avatar": {},
                    "friendly_id": {},
                    "id": {},
                    "username": {}
                  },
                  "type": [
                    "object",
                    "null"
                  ]
                }
              },
              "type": "object"
            },
            "type": "array"
          },
          "friendly_id": {},
          "id": {},
          "last_reply_at": {},
          "priority": {},
          "reply_count": {},
          "resolution": {},
          "resolved_at": {},
          "resource_id": {},
          "resource_type": {},
          "scope": {},
          "stage": {
            "additionalProperties": false,
            "properties": {
              "competition_id": {},
              "end_time": {},
              "friendly_id": {},
              "id": {},
              "name": {},
              "start_time": {},
              "status": {},
              "type": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "stage_category": {
            "additionalProperties": false,
            "properties": {
              "created_at": {},
              "description": {},
              "friendly_id": {},
              "id": {},
              "is_active": {},
              "name": {},
              "sort_order": {},
              "stage_id": {},
              "updated_at": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "stage_category_id": {},
          "stage_id": {},
          "status": {},
          "team": {
            "additionalProperties": false,
            "properties": {
              "avatar": {},
              "description": {},
              "friendly_id": {},
              "id": {},
              "name": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "team_id": {},
          "title": {},
          "updated_at": {},
          "user": {
            "additionalProperties": false,
            "properties": {
              "avatar": {},
              "friendly_id": {},
              "id": {},
              "username": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "user_id": {}
        },
        "type": "object"
      },
      "type": "array"
    },
    "page": {
      "minimum": 1,
      "type": "integer"
    },
    "page_size": {
      "minimum": 1,
      "type": "integer"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    },
    "total_page": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "items",
    "total"
  ],
  "type": "object"
}
```

## `ctf2_list_my_tickets`

List current user global tickets.

Required scopes: `ticket:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "scope": {
      "enum": [
        "global",
        "stage",
        "practice",
        "private_practice",
        "course",
        "class",
        "writeup",
        "account",
        "billing",
        "report"
      ],
      "type": "string"
    },
    "status": {
      "enum": [
        "open",
        "waiting_admin",
        "waiting_user",
        "resolved",
        "closed",
        "cancelled"
      ],
      "type": "string"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "assigned_to": {},
          "assignee": {
            "additionalProperties": false,
            "properties": {
              "avatar": {},
              "friendly_id": {},
              "id": {},
              "username": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "category": {
            "additionalProperties": false,
            "properties": {
              "created_at": {},
              "description": {},
              "friendly_id": {},
              "id": {},
              "is_active": {},
              "name": {},
              "sort_order": {},
              "updated_at": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "category_id": {},
          "closed_at": {},
          "content": {},
          "created_at": {},
          "files": {
            "items": {
              "additionalProperties": false,
              "properties": {
                "cleanup_status": {},
                "created_at": {},
                "download_url": {},
                "expires_at": {},
                "file_type": {},
                "friendly_id": {},
                "id": {},
                "markdown_url": {},
                "mime_type": {},
                "moderation_preview_url": {},
                "moderation_status": {},
                "original_name": {},
                "pending_review_id": {},
                "size": {},
                "updated_at": {},
                "uploaded_by": {},
                "url": {},
                "user": {
                  "additionalProperties": false,
                  "properties": {
                    "avatar": {},
                    "friendly_id": {},
                    "id": {},
                    "username": {}
                  },
                  "type": [
                    "object",
                    "null"
                  ]
                }
              },
              "type": "object"
            },
            "type": "array"
          },
          "friendly_id": {},
          "id": {},
          "last_reply_at": {},
          "priority": {},
          "reply_count": {},
          "resolution": {},
          "resolved_at": {},
          "resource_id": {},
          "resource_type": {},
          "scope": {},
          "stage": {
            "additionalProperties": false,
            "properties": {
              "competition_id": {},
              "end_time": {},
              "friendly_id": {},
              "id": {},
              "name": {},
              "start_time": {},
              "status": {},
              "type": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "stage_category": {
            "additionalProperties": false,
            "properties": {
              "created_at": {},
              "description": {},
              "friendly_id": {},
              "id": {},
              "is_active": {},
              "name": {},
              "sort_order": {},
              "stage_id": {},
              "updated_at": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "stage_category_id": {},
          "stage_id": {},
          "status": {},
          "team": {
            "additionalProperties": false,
            "properties": {
              "avatar": {},
              "description": {},
              "friendly_id": {},
              "id": {},
              "name": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "team_id": {},
          "title": {},
          "updated_at": {},
          "user": {
            "additionalProperties": false,
            "properties": {
              "avatar": {},
              "friendly_id": {},
              "id": {},
              "username": {}
            },
            "type": [
              "object",
              "null"
            ]
          },
          "user_id": {}
        },
        "type": "object"
      },
      "type": "array"
    },
    "page": {
      "minimum": 1,
      "type": "integer"
    },
    "page_size": {
      "minimum": 1,
      "type": "integer"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    },
    "total_page": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "items",
    "total"
  ],
  "type": "object"
}
```

## `ctf2_create_ticket`

Create a global support ticket.

Required scopes: `ticket:write`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "category_id": {
      "format": "uuid",
      "type": "string"
    },
    "content": {
      "maxLength": 10000,
      "minLength": 1,
      "type": "string"
    },
    "file_ids": {
      "items": {
        "format": "uuid",
        "type": "string"
      },
      "maxItems": 10,
      "type": "array",
      "uniqueItems": true
    },
    "priority": {
      "enum": [
        "low",
        "normal",
        "high",
        "urgent"
      ],
      "type": "string"
    },
    "resource_id": {
      "maxLength": 128,
      "minLength": 1,
      "type": "string"
    },
    "resource_type": {
      "maxLength": 64,
      "type": "string"
    },
    "scope": {
      "enum": [
        "global",
        "stage",
        "practice",
        "private_practice",
        "course",
        "class",
        "writeup",
        "account",
        "billing",
        "report"
      ],
      "type": "string"
    },
    "stage_category_id": {
      "format": "uuid",
      "type": "string"
    },
    "title": {
      "maxLength": 200,
      "minLength": 1,
      "type": "string"
    }
  },
  "required": [
    "title",
    "content"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "ticket": {
      "additionalProperties": false,
      "properties": {
        "assigned_to": {},
        "assignee": {
          "additionalProperties": false,
          "properties": {
            "avatar": {},
            "friendly_id": {},
            "id": {},
            "username": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "category": {
          "additionalProperties": false,
          "properties": {
            "created_at": {},
            "description": {},
            "friendly_id": {},
            "id": {},
            "is_active": {},
            "name": {},
            "sort_order": {},
            "updated_at": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "category_id": {},
        "closed_at": {},
        "content": {},
        "created_at": {},
        "files": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "cleanup_status": {},
              "created_at": {},
              "download_url": {},
              "expires_at": {},
              "file_type": {},
              "friendly_id": {},
              "id": {},
              "markdown_url": {},
              "mime_type": {},
              "moderation_preview_url": {},
              "moderation_status": {},
              "original_name": {},
              "pending_review_id": {},
              "size": {},
              "updated_at": {},
              "uploaded_by": {},
              "url": {},
              "user": {
                "additionalProperties": false,
                "properties": {
                  "avatar": {},
                  "friendly_id": {},
                  "id": {},
                  "username": {}
                },
                "type": [
                  "object",
                  "null"
                ]
              }
            },
            "type": "object"
          },
          "type": "array"
        },
        "friendly_id": {},
        "id": {},
        "last_reply_at": {},
        "priority": {},
        "reply_count": {},
        "resolution": {},
        "resolved_at": {},
        "resource_id": {},
        "resource_type": {},
        "scope": {},
        "stage": {
          "additionalProperties": false,
          "properties": {
            "competition_id": {},
            "end_time": {},
            "friendly_id": {},
            "id": {},
            "name": {},
            "start_time": {},
            "status": {},
            "type": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "stage_category": {
          "additionalProperties": false,
          "properties": {
            "created_at": {},
            "description": {},
            "friendly_id": {},
            "id": {},
            "is_active": {},
            "name": {},
            "sort_order": {},
            "stage_id": {},
            "updated_at": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "stage_category_id": {},
        "stage_id": {},
        "status": {},
        "team": {
          "additionalProperties": false,
          "properties": {
            "avatar": {},
            "description": {},
            "friendly_id": {},
            "id": {},
            "name": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "team_id": {},
        "title": {},
        "updated_at": {},
        "user": {
          "additionalProperties": false,
          "properties": {
            "avatar": {},
            "friendly_id": {},
            "id": {},
            "username": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "user_id": {}
      },
      "type": "object"
    }
  },
  "required": [
    "ticket"
  ],
  "type": "object"
}
```

## `ctf2_reply_ticket`

Reply to a global support ticket.

Required scopes: `ticket:write`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "content": {
      "maxLength": 10000,
      "minLength": 1,
      "type": "string"
    },
    "file_ids": {
      "items": {
        "format": "uuid",
        "type": "string"
      },
      "maxItems": 10,
      "type": "array",
      "uniqueItems": true
    },
    "ticket_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "content",
    "ticket_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "reply": {
      "additionalProperties": false,
      "properties": {
        "content": {},
        "created_at": {},
        "files": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "cleanup_status": {},
              "created_at": {},
              "download_url": {},
              "expires_at": {},
              "file_type": {},
              "friendly_id": {},
              "id": {},
              "markdown_url": {},
              "mime_type": {},
              "moderation_preview_url": {},
              "moderation_status": {},
              "original_name": {},
              "pending_review_id": {},
              "size": {},
              "updated_at": {},
              "uploaded_by": {},
              "url": {},
              "user": {
                "additionalProperties": false,
                "properties": {
                  "avatar": {},
                  "friendly_id": {},
                  "id": {},
                  "username": {}
                },
                "type": [
                  "object",
                  "null"
                ]
              }
            },
            "type": "object"
          },
          "type": "array"
        },
        "id": {},
        "is_internal": {},
        "ticket_id": {},
        "updated_at": {},
        "user": {
          "additionalProperties": false,
          "properties": {
            "avatar": {},
            "friendly_id": {},
            "id": {},
            "username": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "user_id": {}
      },
      "type": "object"
    }
  },
  "required": [
    "reply"
  ],
  "type": "object"
}
```

## `ctf2_user_post_tickets_id_transition`

Move own support ticket through allowed user-side statuses.

Required scopes: `ticket:write`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "status": {
      "enum": [
        "open",
        "waiting_admin",
        "closed",
        "cancelled"
      ],
      "type": "string"
    },
    "ticket_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "status",
    "ticket_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "ticket": {
      "additionalProperties": false,
      "properties": {
        "assigned_to": {},
        "assignee": {
          "additionalProperties": false,
          "properties": {
            "avatar": {},
            "friendly_id": {},
            "id": {},
            "username": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "category": {
          "additionalProperties": false,
          "properties": {
            "created_at": {},
            "description": {},
            "friendly_id": {},
            "id": {},
            "is_active": {},
            "name": {},
            "sort_order": {},
            "updated_at": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "category_id": {},
        "closed_at": {},
        "content": {},
        "created_at": {},
        "files": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "cleanup_status": {},
              "created_at": {},
              "download_url": {},
              "expires_at": {},
              "file_type": {},
              "friendly_id": {},
              "id": {},
              "markdown_url": {},
              "mime_type": {},
              "moderation_preview_url": {},
              "moderation_status": {},
              "original_name": {},
              "pending_review_id": {},
              "size": {},
              "updated_at": {},
              "uploaded_by": {},
              "url": {},
              "user": {
                "additionalProperties": false,
                "properties": {
                  "avatar": {},
                  "friendly_id": {},
                  "id": {},
                  "username": {}
                },
                "type": [
                  "object",
                  "null"
                ]
              }
            },
            "type": "object"
          },
          "type": "array"
        },
        "friendly_id": {},
        "id": {},
        "last_reply_at": {},
        "priority": {},
        "reply_count": {},
        "resolution": {},
        "resolved_at": {},
        "resource_id": {},
        "resource_type": {},
        "scope": {},
        "stage": {
          "additionalProperties": false,
          "properties": {
            "competition_id": {},
            "end_time": {},
            "friendly_id": {},
            "id": {},
            "name": {},
            "start_time": {},
            "status": {},
            "type": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "stage_category": {
          "additionalProperties": false,
          "properties": {
            "created_at": {},
            "description": {},
            "friendly_id": {},
            "id": {},
            "is_active": {},
            "name": {},
            "sort_order": {},
            "stage_id": {},
            "updated_at": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "stage_category_id": {},
        "stage_id": {},
        "status": {},
        "team": {
          "additionalProperties": false,
          "properties": {
            "avatar": {},
            "description": {},
            "friendly_id": {},
            "id": {},
            "name": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "team_id": {},
        "title": {},
        "updated_at": {},
        "user": {
          "additionalProperties": false,
          "properties": {
            "avatar": {},
            "friendly_id": {},
            "id": {},
            "username": {}
          },
          "type": [
            "object",
            "null"
          ]
        },
        "user_id": {}
      },
      "type": "object"
    }
  },
  "required": [
    "ticket"
  ],
  "type": "object"
}
```

## `ctf2_get_my_submissions`

List current user submissions.

Required scopes: `submission:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_teams`

List teams.

Required scopes: `team:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_team_my`

Read current user team.

Required scopes: `team:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_teams_id`

Read a team.

Required scopes: `team:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    },
    "team_id": {
      "format": "uuid",
      "type": "string"
    }
  },
  "required": [
    "team_id"
  ],
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "team": {
      "additionalProperties": true,
      "properties": {
        "items": {
          "items": {
            "additionalProperties": true,
            "type": "object"
          },
          "type": "array"
        },
        "total": {
          "minimum": 0,
          "type": "integer"
        }
      },
      "type": "object"
    }
  },
  "required": [
    "team"
  ],
  "type": "object"
}
```

## `ctf2_user_get_learning_events`

List current user learning events.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_get_learning_recommendations`

Read learning recommendations.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "recommendations": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "stats": {
      "additionalProperties": true,
      "type": "object"
    }
  },
  "required": [
    "stats",
    "recommendations"
  ],
  "type": "object"
}
```

## `ctf2_user_get_points`

List current user point balances.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_points_transactions`

List current user point transactions.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_point_shop_products`

List active point shop products.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_point_shop_orders`

List current user point shop orders.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_community_feeds`

List visible community feeds.

Required scopes: `community:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_community_topics`

List community topics.

Required scopes: `community:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_community_discussions`

List visible community discussions.

Required scopes: `community:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_courses`

List published courses.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_classes_my`

List current user class enrollments.

Required scopes: `learning:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_writeups`

List public approved writeups.

Required scopes: `writeup:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## `ctf2_user_get_writeups_my`

List current user writeups.

Required scopes: `writeup:read`.

Input schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "type": "object"
}
```

Output schema:

```json
{
  "additionalProperties": false,
  "properties": {
    "items": {
      "items": {
        "additionalProperties": true,
        "type": "object"
      },
      "type": "array"
    },
    "total": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "type": "object"
}
```

## Error handling

- `401 invalid_token`: reconnect through browser OAuth; revocation is immediate.
- `403 insufficient_scope`: ask before re-authorizing and request only the challenged scope.
- `429`: wait for the `Retry-After` duration before retrying.
- Tool-level errors are returned with `isError: true`; explain the platform error without exposing credentials or sensitive request data.
