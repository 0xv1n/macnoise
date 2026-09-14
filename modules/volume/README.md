# volume

Native disk-image creation and mounted-volume lifecycle operations.

## Modules

### `volume_create`

Creates a read-only UDZO disk image from one literal source directory without overwriting an existing path. The concrete image path is published for scenario dataflow. Cleanup removes only the unchanged image created by that invocation.

### `volume_mount`

Mounts one literal disk image read-only, parses `hdiutil`'s plist response, and publishes the observed whole-disk device and mount point. Cleanup force-detaches only that observed device, and a detach failure fails the scenario cleanup.

```bash
macnoise scenario configs/scenarios/mounted_execution.yaml
```
