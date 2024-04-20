import DeleteOutlined from "@mui/icons-material/DeleteOutlined";
import PlayArrowOutlined from "@mui/icons-material/PlayArrowOutlined";
import RoomOutlined from "@mui/icons-material/RoomOutlined";
import StopOutlined from "@mui/icons-material/StopOutlined";
import type { ComponentProps } from "react";
import type { WorkspaceTransition } from "api/typesGenerated";

type SVGIcon = typeof PlayArrowOutlined;

type SVGIconProps = ComponentProps<SVGIcon>;

const iconByTransition: Record<WorkspaceTransition, SVGIcon> = {
  start: PlayArrowOutlined,
  stop: StopOutlined,
  delete: DeleteOutlined,
  snapshot: RoomOutlined,
};

export const BuildIcon = (
  props: SVGIconProps & { transition: WorkspaceTransition },
) => {
  const Icon = iconByTransition[props.transition];
  return <Icon {...props} />;
};
