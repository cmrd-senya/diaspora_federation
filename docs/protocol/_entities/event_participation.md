---
title: EventParticipation
---

This entity represents a participation in an [Event][event].

See also: [Relayable][relayable]

## Properties

| Property                  | Type                         | Description                                                                                                                          |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `author`                  | [diaspora\*&nbsp;ID][diaspora-id] | The diaspora\* ID of the author of the event participation.                                                                          |
| `guid`                    | [GUID][guid]                 | The GUID of the event participation.                                                                                                 |
| `parent_guid`             | [GUID][guid]                 | The GUID of the [Event][event].                                                                                                      |
| `status`                  | [String][string]             | The participation status, lowercase string as defined in [RFC 5545, Section 3.2.12][status] (`accepted`, `declined` or `tentative`). |
| `author_signature`        | [Signature][signature]       | The signature from the author of the event participation.                                                                            |
| `parent_author_signature` | [Signature][signature]       | The signature from the author of the [Event][event].                                                                                 |

## Examples

### From author

~~~xml
<event_participation>
  <author>alice@example.org</author>
  <guid>92f26ff0b1cb01342ebd55853a9b5d75</guid>
  <parent_guid>bb8371f0b1c901342ebd55853a9b5d75</parent_guid>
  <status>accepted</status>
  <author_signature>dT6KbT7kp0bE+s3//ZErxO1wvVIqtD0lY67i81+dO43B4D2m5kjCdzW240eWt/jZmcHIsdxXf4WHNdrb6ZDnamA8I1FUVnLjHA9xexBITQsSLXrcV88UdammSmmOxl1Ac4VUXqFpdavm6a7/MwOJ7+JHP8TbUO9siN+hMfgUbtY=</author_signature>
  <parent_author_signature/>
</event_participation>
~~~

### From parent author

~~~xml
<event_participation>
  <author>alice@example.org</author>
  <guid>92f26ff0b1cb01342ebd55853a9b5d75</guid>
  <parent_guid>bb8371f0b1c901342ebd55853a9b5d75</parent_guid>
  <status>accepted</status>
  <author_signature>dT6KbT7kp0bE+s3//ZErxO1wvVIqtD0lY67i81+dO43B4D2m5kjCdzW240eWt/jZmcHIsdxXf4WHNdrb6ZDnamA8I1FUVnLjHA9xexBITQsSLXrcV88UdammSmmOxl1Ac4VUXqFpdavm6a7/MwOJ7+JHP8TbUO9siN+hMfgUbtY=</author_signature>
  <parent_author_signature>gWasNPpSnMcKBIMWyzfoVO6sr8eRYkhUqy3PIkkh53n/ki+DM9mnh3ayotI0+6un9aq1N3XkS7Vn05ZD3+nHVby6i21XkYgPnbD8pWYuBBj7VGPyahT70BUs/vSvY8KX8V3wYfsPsaiAgJsAFg2UHYdY3r4/oWdIIbBZc21O3zk=</parent_author_signature>
</event_participation>
~~~

[diaspora-id]: {{ site.baseurl }}/federation/types.html#diaspora-id
[guid]: {{ site.baseurl }}/federation/types.html#guid
[string]: {{ site.baseurl }}/federation/types.html#string
[status]: https://tools.ietf.org/html/rfc5545#section-3.2.12
[signature]: {{ site.baseurl }}/federation/types.html#signature
[event]: {{ site.baseurl }}/entities/event.html
[relayable]: {{ site.baseurl }}/federation/relayable.html
